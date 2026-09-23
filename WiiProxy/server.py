import gzip
import http.server
import io
import re
import select
import socket
import socketserver
import ssl
import urllib.error
import urllib.parse
import urllib.request

try:
    from PIL import Image

    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class HybridProxy(http.server.BaseHTTPRequestHandler):
    last_origin = "https://ja.m.wikipedia.org"

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (
            ConnectionResetError,
            BrokenPipeError,
            TimeoutError,
            socket.error,
        ):
            pass

    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {format % args}")

    def do_CONNECT(self):
        address = self.path.split(":")
        host = address[0].strip()
        port = int(address[1]) if len(address) > 1 else 443

        print(f"[CONNECT Tunnel] Opening tunnel to {host}:{port}")
        remote = None
        try:
            remote = socket.create_connection((host, port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()

            sockets = [self.connection, remote]
            keep_alive = True
            while keep_alive:
                readable, _, errorable = select.select(sockets, [], sockets, 10)
                if errorable:
                    break
                for s in readable:
                    other = (
                        remote if s is self.connection else self.connection
                    )
                    try:
                        data = s.recv(8192)
                        if data:
                            other.sendall(data)
                        else:
                            keep_alive = False
                            break
                    except Exception:
                        keep_alive = False
                        break
        except Exception as e:
            print(f"[CONNECT Error] Failed to tunnel {host}:{port} - {e}")
            try:
                self.send_error(502, f"Bad Gateway: {e}")
            except Exception:
                pass
        finally:
            if remote:
                try:
                    remote.close()
                except Exception:
                    pass

    def do_GET(self):
        self.handle_request_method("GET")

    def do_POST(self):
        self.handle_request_method("POST")

    def do_HEAD(self):
        self.handle_request_method("HEAD")

    def clean_raw_path(self, raw_path):
        cleaned = raw_path
        pattern = r"(?:/?x-safari-https:/?|/?redirect\.x\.com/?)+"
        while re.search(pattern, cleaned, flags=re.IGNORECASE):
            cleaned = re.sub(pattern, "/", cleaned, flags=re.IGNORECASE)

        cleaned = re.sub(r"^/+", "/", cleaned)

        while re.search(r"https?://https?://", cleaned, re.IGNORECASE):
            cleaned = re.sub(
                r"https?://(https?://)", r"\1", cleaned, flags=re.IGNORECASE
            )

        cleaned = re.sub(
            r'(?:%20|\s+)(?:title|nonce|defer|crossorigin|style|width|height|sizes|async|media|rel)=["\']?.*$',
            "",
            cleaned,
            flags=re.IGNORECASE,
        )
        return cleaned

    def handle_request_method(self, method, redirect_count=0):
        if redirect_count > 5:
            print("[Loop Shield] Too many internal redirects")
            self.send_error(508, "Loop Detected")
            return

        server_ip, server_port = self.server.server_address
        if server_ip == "0.0.0.0":
            server_ip = self.connection.getsockname()[0]
        proxy_host = f"{server_ip}:{server_port}"

        # 不要なトラッキングやノイズリクエストの遮断
        bad_paths = [
            "gen_204",
            "httpservice/retry",
            "pagead",
            "og/_/js",
            "google-analytics.com",
            "doubleclick.net",
            "analytics",
            "gtm.js",
            "ga.js",
            "fbevents.js",
            "news.wapp.wii.com",
        ]
        if any(bad in self.path.lower() for bad in bad_paths):
            try:
                self.send_response(204)
                self.end_headers()
            except Exception:
                pass
            return

        host_header = self.headers.get("Host", "")
        is_forward_proxy = False
        req_path = self.path

        if proxy_host in req_path:
            req_path = re.sub(
                r"^https?://" + re.escape(proxy_host) + r"/?", "/", req_path
            )

        if req_path.startswith("http://") or req_path.startswith("https://"):
            target_url = req_path
            is_forward_proxy = True
        elif (
            host_header
            and host_header != proxy_host
            and not req_path.startswith(f"http://{proxy_host}")
        ):
            target_url = (
                f"https://{host_header}{req_path}"
                if not req_path.startswith("http")
                else req_path
            )
            is_forward_proxy = True
        else:
            raw_path = req_path[1:] if req_path.startswith("/") else req_path

            if not raw_path or raw_path.strip() == "":
                if method != "GET":
                    self.send_response(200)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()

                portal_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Retro Proxy Portal</title>
    <style>
        body {{ font-family: sans-serif; background: #f0f0f0; margin: 0; padding: 15px; color: #333; }}
        h1 {{ font-size: 20px; border-bottom: 2px solid #0066cc; padding-bottom: 5px; color: #0066cc; }}
        p {{ font-size: 14px; margin-bottom: 15px; }}
        .card {{ background: #fff; border: 1px solid #ccc; padding: 12px; margin-bottom: 10px; border-radius: 4px; display: block; text-decoration: none; color: #000; }}
        .card:hover {{ background: #e8f4ff; border-color: #0066cc; }}
        .title {{ font-weight: bold; font-size: 16px; color: #0066cc; }}
        .desc {{ font-size: 12px; color: #666; margin-top: 3px; }}
        .url-box {{ margin-top: 15px; background: #fff; padding: 10px; border: 1px solid #ccc; margin-bottom: 15px; }}
        input[type="text"] {{ width: 65%; padding: 5px; font-size: 14px; }}
        input[type="submit"] {{ padding: 5px 10px; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>Quick Access Menu</h1>
    <p>Proxy running on <b>{proxy_host}</b> (Forward & Reverse Mode)</p>

    <div class="url-box">
        <form onsubmit="
            var u = document.getElementById('u').value.trim();
            if (!u) return false;
            if (!/^https?:\\/\\//i.test(u)) {{
                u = 'https://' + u;
            }}
            location.href = '/' + u;
            return false;
        ">
            <b>Enter a URL and go:</b><br>
            <input type="text" id="u" value="https://ja.m.wikipedia.org" placeholder="ja.m.wikipedia.org">
            <input type="submit" value="Enter">
        </form>
    </div>

    <h3>Lightweight site List</h3>
    <a class="card" href="/http://frogfind.com">
        <div class="title">FrogFind</div>
        <div class="desc">Lightweight search engine for retro browsers</div>
    </a>

    <a class="card" href="/https://inv.nadeko.net">
        <div class="title">Invidious (YouTube)</div>
        <div class="desc">Lightweight YouTube viewer that does not use Google Scripts.</div>
    </a>

    <a class="card" href="/https://ja.m.wikipedia.org">
        <div class="title">Wikipedia</div>
        <div class="desc">Japanese Wikipedia (Mobile View)</div>
    </a>
</body>
</html>
"""
                try:
                    self.wfile.write(portal_html.encode("utf-8"))
                except Exception:
                    pass
                return

            raw_path = self.clean_raw_path(raw_path)

            if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", raw_path):
                target_url = "https://" + raw_path
            elif raw_path.startswith("http://") or raw_path.startswith(
                "https://"
            ):
                target_url = raw_path
            elif raw_path.startswith("//"):
                target_url = "https:" + raw_path
            elif raw_path.startswith("/"):
                target_url = HybridProxy.last_origin + raw_path
            else:
                target_url = HybridProxy.last_origin + "/" + raw_path

        # Googleの軽量HTML固定処理
        if "google.com" in target_url:
            if target_url.startswith("http://"):
                target_url = target_url.replace("http://", "https://", 1)
            if "google.com/search" in target_url and "gbv=" not in target_url:
                delimiter = "&" if "?" in target_url else "?"
                target_url += f"{delimiter}gbv=1"

        parsed_target = urllib.parse.urlparse(target_url)

        # last_origin の更新
        ignorable_domains = [
            "gstatic.com",
            "ytimg.com",
            "googlevideo.com",
            "th.bing.com",
            "media.loom-app.com",
            "wikimedia.org",
            "wapp.wii.com",
        ]

        if parsed_target.scheme and parsed_target.netloc:
            if not any(d in parsed_target.netloc for d in ignorable_domains):
                HybridProxy.last_origin = (
                    f"{parsed_target.scheme}://{parsed_target.netloc}"
                )

        print(
            f"[{method}] Proxying ({'Forward' if is_forward_proxy else 'Reverse'}): {target_url}"
        )

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.options &= ~ssl.OP_NO_SSLv3
                ctx.options &= ~ssl.OP_NO_TLSv1
                ctx.options &= ~ssl.OP_NO_TLSv1_1
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception:
                pass

            content_length = int(self.headers.get("Content-Length", 0))
            req_body = None
            if content_length > 0:
                max_bytes = min(content_length, 50 * 1024 * 1024)
                req_body = self.rfile.read(max_bytes)

            headers = {}
            for key, value in self.headers.items():
                if key.lower() in [
                    "host",
                    "connection",
                    "content-length",
                    "accept-encoding",
                    "user-agent",
                ]:
                    continue
                headers[key] = value

            headers["Host"] = parsed_target.netloc
            headers["Accept-Encoding"] = "identity"
            headers["User-Agent"] = (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X)"
                " AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60"
            )

            req = urllib.request.Request(
                target_url, data=req_body, headers=headers, method=method
            )
            opener = urllib.request.build_opener(
                NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx)
            )

            try:
                response = opener.open(req, timeout=15)
            except urllib.error.HTTPError as e:
                response = e

            status_code = response.code
            content_type = response.headers.get("Content-Type", "").lower()

            # 301/302 リダイレクト処理
            if status_code in (301, 302, 303, 307, 308):
                loc = response.headers.get("Location", "")
                if loc:
                    loc = re.sub(
                        r"^(?:x-safari-https:/?)+",
                        "https://",
                        loc,
                        flags=re.IGNORECASE,
                    )
                    absolute_loc = urllib.parse.urljoin(target_url, loc)
                    absolute_loc = self.clean_raw_path(absolute_loc)

                    if absolute_loc.rstrip("/") != target_url.rstrip("/"):
                        print(
                            f"[PSP Auto Redirect] Intercepting {status_code} ->"
                            f" {absolute_loc}"
                        )
                        if is_forward_proxy:
                            self.path = absolute_loc
                        else:
                            self.path = f"/{absolute_loc}"
                        return self.handle_request_method(
                            method, redirect_count + 1
                        )

            body = response.read() if method != "HEAD" else b""

            content_encoding = response.headers.get(
                "Content-Encoding", ""
            ).lower()
            if "gzip" in content_encoding:
                try:
                    body = gzip.decompress(body)
                except Exception:
                    pass

            # 画像変換処理（PIL未対応のSVGやエラー時はスキップして元データを維持）
            if HAS_PIL and method != "HEAD" and ("image/" in content_type):
                if "svg" not in content_type:
                    try:
                        img = Image.open(io.BytesIO(body))
                        img.thumbnail((480, 272))
                        bg = Image.new("RGB", img.size, (255, 255, 255))
                        if img.mode in ("RGBA", "LA") or (
                            img.mode == "P" and "transparency" in img.info
                        ):
                            img = img.convert("RGBA")
                            bg.paste(img, mask=img.split()[3])
                        else:
                            bg.paste(img)

                        out_io = io.BytesIO()
                        bg.save(out_io, format="JPEG", quality=55)
                        body = out_io.getvalue()
                        content_type = "image/jpeg"
                    except Exception:
                        pass

            if method != "HEAD" and (
                "text/html" in content_type or "text/css" in content_type
            ):
                text_content = body.decode("utf-8", errors="ignore")

                if "text/html" in content_type:
                    # 見出しボタン・折りたたみ・アコーディオン等のUI操作スクリプトのみ許可
                    def filter_script_tag(match):
                        full_tag = match.group(0)
                        attrs = match.group(1)
                        content = match.group(2)

                        # 害のある追跡・広告用スクリプトは除外
                        block_keywords = [
                            "analytics",
                            "gtm",
                            "facebook",
                            "twitter",
                            "adsystem",
                            "doubleclick",
                            "beacon",
                            "telemetry",
                        ]
                        if any(kw in full_tag.lower() for kw in block_keywords):
                            return ""

                        # 重いWebアプリケーション（React/Vueなど）のライブラリはフリーズ防止のため除外
                        src_match = re.search(
                            r'src=["\']([^"\']+)["\']', attrs, re.IGNORECASE
                        )
                        if src_match:
                            src_url = src_match.group(1).lower()
                            if any(
                                lib in src_url
                                for lib in [
                                    "react",
                                    "vue",
                                    "angular",
                                    "polyfill",
                                    "webpack",
                                ]
                            ):
                                return ""
                            # UI開閉用の軽量ライブラリ（jQueryやWikipediaの基本ナビ等）は通過
                            return full_tag

                        # インラインスクリプトの場合：見出し・ボタン操作・アコーディオンに関するキーワードを含むか判定
                        ui_keywords = [
                            "toggle",
                            "accordion",
                            "collapse",
                            "expand",
                            "section",
                            "heading",
                            "button",
                            "menu",
                            "collapsible",
                            "onclick",
                            "display",
                            "style.display",
                        ]
                        content_lower = content.lower()

                        # UI操作キーワードが含まれており、かつ小さめのスクリプト(15KB以下)であれば許可
                        if any(
                            kw in content_lower for kw in ui_keywords
                        ) and len(content) < 15000:
                            return full_tag

                        # その他の巨大・無関係なインラインスクリプトは削除
                        return ""

                    script_pattern = r"(?is)<script\b([^>]*)>(.*?)</script>"
                    text_content = re.sub(
                        script_pattern, filter_script_tag, text_content
                    )

                if is_forward_proxy:
                    text_content = re.sub(
                        r'href=["\']https://([^"\']+)["\']',
                        r'href="http://\1"',
                        text_content,
                        flags=re.IGNORECASE,
                    )
                    text_content = re.sub(
                        r'src=["\']https://([^"\']+)["\']',
                        r'src="http://\1"',
                        text_content,
                        flags=re.IGNORECASE,
                    )
                else:

                    def replace_url(match):
                        attr = match.group(1)
                        quote = match.group(2)
                        url_raw = match.group(3).strip()

                        if (
                            not url_raw
                            or proxy_host in url_raw
                            or url_raw.startswith(
                                (
                                    "data:",
                                    "mailto:",
                                    "javascript:",
                                    "#",
                                    "tel:",
                                )
                            )
                        ):
                            return match.group(0)

                        if url_raw.startswith("//"):
                            absolute_url = "https:" + url_raw
                        elif url_raw.startswith(
                            "http://"
                        ) or url_raw.startswith("https://"):
                            absolute_url = url_raw
                        else:
                            absolute_url = urllib.parse.urljoin(
                                target_url, url_raw
                            )

                        absolute_url = self.clean_raw_path(absolute_url)
                        return (
                            f'{attr}={quote}http://{proxy_host}/{absolute_url}{quote}'
                        )

                    pattern = r"""(?i)\b(src|href|action|srcset|data-src|poster)\s*=\s*(["'])(.*?)\2"""
                    text_content = re.sub(pattern, replace_url, text_content)

                    def replace_css_url(match):
                        url_raw = match.group(1).strip("'\" ")
                        if (
                            not url_raw
                            or proxy_host in url_raw
                            or url_raw.startswith("data:")
                        ):
                            return match.group(0)
                        if url_raw.startswith("//"):
                            abs_url = "https:" + url_raw
                        elif url_raw.startswith(
                            "http://"
                        ) or url_raw.startswith("https://"):
                            abs_url = url_raw
                        else:
                            abs_url = urllib.parse.urljoin(target_url, url_raw)
                        abs_url = self.clean_raw_path(abs_url)
                        return f"url('http://{proxy_host}/{abs_url}')"

                    text_content = re.sub(
                        r"""url\(([^)]+)\)""",
                        replace_css_url,
                        text_content,
                        flags=re.IGNORECASE,
                    )

                body = text_content.encode("utf-8")

            self.send_response(status_code)

            ignore_resp_headers = [
                "transfer-encoding",
                "content-encoding",
                "content-length",
                "connection",
                "keep-alive",
                "server",
                "content-type",
            ]

            for k, v in response.headers.items():
                if k.lower() not in ignore_resp_headers:
                    self.send_header(k, v)

            if content_type:
                self.send_header("Content-Type", content_type)

            self.send_header("Content-Length", str(len(body)))
            self.end_headers()

            if method != "HEAD":
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

        except (
            ConnectionResetError,
            BrokenPipeError,
            TimeoutError,
            socket.error,
        ):
            pass
        except Exception as e:
            print(f"Error ({method}): {e}")


PORT = 8000
if __name__ == "__main__":
    with ThreadedTCPServer(("", PORT), HybridProxy) as httpd:
        print(f"Hybrid Proxy started on port {PORT} (OK)")
        httpd.serve_forever()