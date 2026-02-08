from flask import Flask, jsonify
import requests
import pytz
import re
import time
import json
import os
import base64
import binascii
from urllib.parse import urljoin
from datetime import datetime, timedelta, timezone
from Crypto.Cipher import AES


# ============================================
# Zerohazaar Client (decrypt events + links)
# ============================================
class ZerohazaarClient:
    EVENTS_URL = "https://zerohazaarop.store/events.txt"
    LINKS_BASE_URL = "https://zerohazaarop.store/"

    KEY = b"l9K5bT5xC1wP7pK1"
    IV = b"k5K4nN7oU8hL6l19"

    DEFAULT_MATCH_DURATION = timedelta(hours=2)
    PRELIVE_WINDOW = timedelta(minutes=10)

    HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

    def __init__(self, tz_name="Asia/Yangon"):
        self.tz = pytz.timezone(tz_name)

    # ---------- small helpers ----------
    def _is_hex(self, s: str) -> bool:
        s = (s or "").strip()
        return len(s) % 2 == 0 and self.HEX_RE.fullmatch(s) is not None

    def _try_decode(self, data: str):
        data = (data or "").strip()

        # HEX
        if self._is_hex(data):
            return binascii.unhexlify(data), "HEX"

        # BASE64 (with padding fix)
        b64 = re.sub(r"\s+", "", data)
        if len(b64) % 4:
            b64 += "=" * (4 - (len(b64) % 4))

        try:
            return base64.b64decode(b64, validate=False), "BASE64"
        except Exception:
            return base64.urlsafe_b64decode(b64), "BASE64_URLSAFE"

    def _pkcs7_unpad(self, buf: bytes) -> bytes:
        if not buf:
            return buf
        pad = buf[-1]
        if pad < 1 or pad > 16:
            return buf
        return buf[:-pad]

    def _decrypt_text(self, encrypted_text: str) -> str:
        cipher_bytes, _ = self._try_decode(encrypted_text)
        cipher = AES.new(self.KEY, AES.MODE_CBC, self.IV)
        decrypted = cipher.decrypt(cipher_bytes)
        return self._pkcs7_unpad(decrypted).decode("utf-8", errors="ignore")

    def _fetch_text(self, url: str, timeout=20) -> str:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        return (r.text or "").strip()

    def fetch_and_decrypt_json(self, url: str):
        try:
            encrypted = self._fetch_text(url)
            plain = self._decrypt_text(encrypted)
            return json.loads(plain), None
        except Exception as e:
            return None, str(e)

    def _parse_utc_datetime(self, date_str: str, time_str: str) -> datetime:
        dt = datetime.strptime(f"{date_str} {time_str}", "%d/%m/%Y %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)

    def get_start_end_mm(self, event: dict):
        if not event.get("date") or not event.get("time"):
            return None, None

        start_mm = self._parse_utc_datetime(event["date"].strip(), event["time"].strip()).astimezone(self.tz)

        if event.get("end_time"):
            try:
                end_mm = self._parse_utc_datetime(event["date"].strip(), event["end_time"].strip()).astimezone(self.tz)
            except Exception:
                end_mm = start_mm + self.DEFAULT_MATCH_DURATION
        else:
            end_mm = start_mm + self.DEFAULT_MATCH_DURATION

        return start_mm, end_mm

    def get_status(self, event: dict) -> str:
        start_mm, end_mm = self.get_start_end_mm(event)
        if not start_mm:
            return "UPCOMING"

        now_mm = datetime.now(self.tz)

        if now_mm > end_mm:
            return "ENDED"

        if now_mm < (start_mm - self.PRELIVE_WINDOW):
            return "UPCOMING"

        if (start_mm - self.PRELIVE_WINDOW) <= now_mm < start_mm:
            return "PRELIVE"

        return "LIVE"

    def should_fetch_links(self, status: str) -> bool:
        return status in ("PRELIVE", "LIVE")

    def fmt_ampm(self, dt: datetime):
        return dt.strftime("%d-%m-%Y %I:%M %p") if dt else None

    def normalize_event(self, item):
        if not isinstance(item, dict):
            return None

        ev = item.get("event")
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except Exception:
                return None

        return ev if isinstance(ev, dict) else None

    def clean_live_links(self, live_links):
        if not isinstance(live_links, list):
            return live_links

        out = []
        for it in live_links:
            if not isinstance(it, dict):
                continue

            obj = it.copy()
            token_api = obj.get("tokenApi")
            if isinstance(token_api, str) and token_api.strip():
                try:
                    obj["tokenApi"] = json.loads(token_api)
                except Exception:
                    pass
            out.append(obj)
        return out

    def fetch_football_events(self):
        events, err = self.fetch_and_decrypt_json(self.EVENTS_URL)
        if err or not isinstance(events, list):
            print(f"[Zerohazaar] events error: {err}")
            return []

        results = []
        for item in events:
            ev = self.normalize_event(item)
            if not ev:
                continue

            if ev.get("category", "").lower() != "football":
                continue

            status = self.get_status(ev)
            if status == "ENDED":
                continue

            start_mm, end_mm = self.get_start_end_mm(ev)

            # fetch live_links only for PRELIVE/LIVE
            live_links = []
            if ev.get("links") and self.should_fetch_links(status):
                links_path = ev.get("links")
                links_url = links_path if str(links_path).startswith("http") else urljoin(self.LINKS_BASE_URL, str(links_path))

                links_data, links_err = self.fetch_and_decrypt_json(links_url)
                if links_err:
                    live_links = [{"name": "error", "link": "", "api": "", "tokenApi": links_err}]
                else:
                    live_links = self.clean_live_links(links_data)

            # -------- NEW: league from zerohazaar (eventName) --------
            league_name = (ev.get("eventName") or "").strip()

            results.append({
                "status": status,
                "matchTime": self.fmt_ampm(start_mm),
                "endTime": self.fmt_ampm(end_mm),

                "league": league_name,  # <--- NEW

                "home": {"name": ev.get("teamAName", ""), "logo": ev.get("teamAFlag", "")},
                "away": {"name": ev.get("teamBName", ""), "logo": ev.get("teamBFlag", "")},
                "live_links": live_links,
            })

        # sort: LIVE first, then PRELIVE, then UPCOMING
        def status_rank(s):
            return {"LIVE": 0, "PRELIVE": 1, "UPCOMING": 2}.get(s, 99)

        def parse_match_time(s):
            if not s:
                return datetime.max.replace(tzinfo=self.tz)
            dt = datetime.strptime(s, "%d-%m-%Y %I:%M %p")
            return dt.replace(tzinfo=self.tz)

        results.sort(key=lambda x: (status_rank(x.get("status")), parse_match_time(x.get("matchTime"))))
        return results


# ============================================
# Main API (SocoLive + enrich)
# ============================================
class SocoLiveAPI:
    MAIN_REFERER = "https://socolivev.co/"
    MATCH_URL_TEMPLATE = "https://json.vnres.co/match/matches_{}.json"
    STREAM_URL_TEMPLATE = "https://json.vnres.co/room/{}/detail.json"

    VIDEO_LINK_API = "https://live.singapore2dmm.com/football/video.json"

    STORAGE_PATH = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "storage", "app", "data", "scrape.json")
    )

    REPLACE_LOGO_URL = "https://sta.vnres.co/file/common/20250522/1a38e8271ee60fd82b2129330af59968.png"
    REPLACEMENT_LOGO = "https://football.redsport.live//storage/01HQNMEPGZC4XHY6ZWW022VAYN.png"

    def __init__(self):
        self.app = Flask(__name__)
        self.tz = pytz.timezone("Asia/Yangon")

        self.zerohazaar = ZerohazaarClient("Asia/Yangon")

        self.app.add_url_rule("/matches", "get_matches", self.get_matches, methods=["GET"])
        self.app.register_error_handler(404, self.not_found)

    # ---------- common helpers ----------
    @staticmethod
    def normalize_team(name: str) -> str:
        return (name or "").strip().lower()

    @staticmethod
    def ensure_dir_for_file(path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    @staticmethod
    def safe_get_json(url: str, timeout=12):
        try:
            r = requests.get(url, timeout=timeout)
            if r.ok:
                return r.json()
        except Exception as e:
            print(f"[JSON Error] {url} -> {e}")
        return None

    # ---------- soco stream ----------
    def fetch_soco_stream(self, room_num: str):
        try:
            r = requests.get(self.STREAM_URL_TEMPLATE.format(room_num), timeout=12)
            if not r.ok:
                return {"m3u8": None, "hdM3u8": None}

            m = re.search(r"detail\((.*)\)", r.text)
            if not m:
                return {"m3u8": None, "hdM3u8": None}

            data = json.loads(m.group(1))
            if data.get("code") != 200:
                return {"m3u8": None, "hdM3u8": None}

            stream = data.get("data", {}).get("stream", {}) or {}
            return {"m3u8": stream.get("m3u8"), "hdM3u8": stream.get("hdM3u8")}

        except Exception as e:
            print(f"[Stream Error] {e}")
            return {"m3u8": None, "hdM3u8": None}

    # ---------- soco matches ----------
    def fetch_soco_matches_for_date(self, date_str: str):
        url = self.MATCH_URL_TEMPLATE.format(date_str)
        matches_list = []

        try:
            r = requests.get(url, timeout=12)
            if not r.ok:
                return matches_list

            m = re.search(r"matches_\d+\((.*)\)", r.text)
            if not m:
                return matches_list

            data = json.loads(m.group(1))
            if data.get("code") != 200:
                return matches_list

            items = data.get("data", []) or []

            now_ts = int(time.time())
            prelive_threshold = now_ts + 600  # 10 minutes

            for item in items:
                try:
                    match_ts = int(item["matchTime"] / 1000)

                    dt_utc = datetime.fromtimestamp(match_ts, tz=pytz.UTC)
                    dt_mm = dt_utc.astimezone(self.tz)
                    formatted_time = dt_mm.strftime("%Y-%m-%d %H:%M:%S")

                    is_live = (now_ts >= match_ts) or (prelive_threshold > match_ts)

                    match_obj = {
                        "date": formatted_time,
                        "league": self.replace_league(item.get("subCateName", "")),
                        "home": {
                            "name": item.get("hostName", ""),
                            "logo": self.replace_logo(item.get("hostIcon", "")),
                            "score": str(item.get("hostScore", "0")),
                        },
                        "away": {
                            "name": item.get("guestName", ""),
                            "logo": self.replace_logo(item.get("guestIcon", "")),
                            "score": str(item.get("guestScore", "0")),
                        },
                        "video_links": [],
                    }

                    if is_live:
                        anchors = item.get("anchors", []) or []
                        for a in anchors[:1]:
                            room_num = (a.get("anchor", {}) or {}).get("roomNum")
                            if not room_num:
                                continue

                            stream = self.fetch_soco_stream(room_num)

                            if stream.get("m3u8"):
                                match_obj["video_links"].append({
                                    "name": "Soco SD",
                                    "url": stream["m3u8"],
                                    "referer": self.MAIN_REFERER,
                                })

                            if stream.get("hdM3u8"):
                                match_obj["video_links"].append({
                                    "name": "Soco HD",
                                    "url": stream["hdM3u8"],
                                    "referer": self.MAIN_REFERER,
                                })

                    matches_list.append(match_obj)

                except Exception as e:
                    print(f"[Match Parse Error] {e}")

        except Exception as e:
            print(f"[Match Fetch Error] {e}")

        return matches_list

    # ---------- other APIs ----------
    def fetch_singapore_video_tags(self):
        data = self.safe_get_json(self.VIDEO_LINK_API)
        return data if isinstance(data, list) else []

    # ---------- normalize zerohazaar link (api -> referer) ----------
    @staticmethod
    def normalize_zerohazaar_link(item: dict):
        if not isinstance(item, dict):
            return None

        name = (item.get("name") or "").strip() or "Zerohazaar"
        url = (item.get("url") or item.get("link") or "").strip()
        if not url:
            return None

        referer = (item.get("referer") or "").strip()
        if not referer:
            referer = (item.get("api") or "").strip()

        token_api = item.get("tokenApi")
        if isinstance(token_api, str) and token_api.strip():
            try:
                token_api = json.loads(token_api)
            except Exception:
                pass

        out = {"name": name, "url": url}
        if referer:
            out["referer"] = referer
        if token_api not in (None, "", [], {}):
            out["tokenApi"] = token_api

        return out

    @staticmethod
    def normalize_zerohazaar_links(live_links):
        if not isinstance(live_links, list):
            return []
        out = []
        for x in live_links:
            n = SocoLiveAPI.normalize_zerohazaar_link(x)
            if n:
                out.append(n)
        return out

    # ---------- merge helpers ----------
    @staticmethod
    def add_unique_link(match_obj: dict, link_obj: dict, insert_at=None):
        if not isinstance(link_obj, dict):
            return

        links = match_obj.get("video_links", [])
        if link_obj in links:
            return

        if insert_at is None:
            links.append(link_obj)
        else:
            idx = max(0, min(int(insert_at), len(links)))
            links.insert(idx, link_obj)

        match_obj["video_links"] = links

    def enrich_with_singapore_tags(self, matches, video_tags):
        if not video_tags:
            return matches

        for m in matches:
            home = self.normalize_team(m["home"]["name"])
            away = self.normalize_team(m["away"]["name"])

            for v in video_tags:
                tag = self.normalize_team(v.get("tag", ""))
                if not tag:
                    continue

                if tag == home or tag == away:
                    self.add_unique_link(m, v, insert_at=0)

        return matches

    def enrich_with_zerohazaar_links(self, matches, zerohazaar_events):
        if not zerohazaar_events:
            return matches

        for m in matches:
            home = self.normalize_team(m["home"]["name"])
            away = self.normalize_team(m["away"]["name"])

            for zev in zerohazaar_events:
                zhome = self.normalize_team((zev.get("home", {}) or {}).get("name", ""))
                zaway = self.normalize_team((zev.get("away", {}) or {}).get("name", ""))

                paired = (home == zhome and away == zaway)
                fallback_or = (home == zhome or away == zaway)

                if paired or fallback_or:
                    zleague = (zev.get("league") or "").strip()
                    if zleague:
                        m["league"] = zleague

                    links = self.normalize_zerohazaar_links(zev.get("live_links", []) or [])
                    for link in links:
                        self.add_unique_link(m, link, insert_at=2)

        return matches

    @staticmethod
    def remove_duplicate_matches(matches):
        seen = set()
        out = []

        for m in matches:
            key = (
                SocoLiveAPI.normalize_team(m["home"]["name"]),
                SocoLiveAPI.normalize_team(m["away"]["name"]),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(m)

        return out

    # ---------- main builder ----------
    def build_matches(self):
        now = datetime.now(self.tz)

        dates = [
            now.strftime("%Y%m%d"),
            (now + timedelta(days=1)).strftime("%Y%m%d"),
        ]

        all_matches = []
        for d in dates:
            all_matches.extend(self.fetch_soco_matches_for_date(d))

        singapore_tags = self.fetch_singapore_video_tags()
        zerohazaar_events = self.zerohazaar.fetch_football_events()

        all_matches = self.enrich_with_singapore_tags(all_matches, singapore_tags)
        all_matches = self.enrich_with_zerohazaar_links(all_matches, zerohazaar_events)

        all_matches = self.remove_duplicate_matches(all_matches)
        return all_matches

    def save_matches(self, matches):
        try:
            self.ensure_dir_for_file(self.STORAGE_PATH)
            with open(self.STORAGE_PATH, "w", encoding="utf-8") as f:
                json.dump(matches, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[Storage Write Error] {e}")

    # ---------- flask routes ----------
    def get_matches(self):
        matches = self.build_matches()
        self.save_matches(matches)
        return jsonify(matches), 200

    def not_found(self, error):
        return jsonify({"error": "Not Found"}), 404

    # ---------- replacements ----------
    @staticmethod
    def replace_logo(url: str) -> str:
        if url == SocoLiveAPI.REPLACE_LOGO_URL:
            return SocoLiveAPI.REPLACEMENT_LOGO
        return url

    @staticmethod
    def replace_league(name: str) -> str:
        return "Premier League" if name == "ENG PR" else name


if __name__ == "__main__":
    api = SocoLiveAPI()
    try:
        matches = api.build_matches()
        api.save_matches(matches)
        print("Done ✅")
    except Exception as e:
        print(f"[Startup Error] {e}")
