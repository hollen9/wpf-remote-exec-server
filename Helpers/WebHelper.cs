using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace wpf_remoteexec.Helpers
{
    internal static class WebHelper
    {
        public static string GetPwdFromRequest(HttpListenerRequest req)
        {
            string pwd = null;

            // 先讀 POST 表單
            if ("POST".Equals(req.HttpMethod, StringComparison.OrdinalIgnoreCase) &&
                req.HasEntityBody &&
                req.ContentType != null &&
                req.ContentType.IndexOf("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                using (var sr = new StreamReader(req.InputStream, req.ContentEncoding ?? Encoding.UTF8))
                {
                    var body = sr.ReadToEnd();
                    var nv = ParseFormUrlEncoded(body);
                    if (nv.ContainsKey("pwd")) pwd = nv["pwd"];
                }
            }

            // 沒有就讀 GET Query
            if (pwd == null)
            {
                var query = req.Url.Query; // 例如 "?pwd=abc"
                if (!string.IsNullOrEmpty(query) && query.Length > 1)
                {
                    var nv = ParseFormUrlEncoded(query.Substring(1));
                    if (nv.ContainsKey("pwd")) pwd = nv["pwd"];
                }
            }
            return pwd;
        }

        public static Dictionary<string, string> ParseFormUrlEncoded(string s)
        {
            var dict = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(s)) return dict;

            var pairs = s.Split('&');
            foreach (var p in pairs)
            {
                var kv = p.Split(new[] { '=' }, 2);
                var k = UrlDecodePlus(kv[0]);
                var v = kv.Length > 1 ? UrlDecodePlus(kv[1]) : "";
                dict[k] = v;
            }
            return dict;
        }

        // 簡易解碼：先把 '+' 視為空白，再做 Uri.UnescapeDataString
        public static string UrlDecodePlus(string s)
        {
            if (s == null) return "";
            return Uri.UnescapeDataString(s.Replace("+", " "));
        }

        // 一次解析 POST 表單與 Query（POST 優先，Query 補缺）
        public static Dictionary<string, string> ReadFields(HttpListenerRequest req)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // 先讀 POST（application/x-www-form-urlencoded）
            if ("POST".Equals(req.HttpMethod, StringComparison.OrdinalIgnoreCase) &&
                req.HasEntityBody &&
                req.ContentType != null &&
                req.ContentType.IndexOf("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                using (var sr = new StreamReader(req.InputStream, req.ContentEncoding ?? Encoding.UTF8))
                {
                    var body = sr.ReadToEnd();
                    foreach (var kv in ParseFormUrlEncoded(body))
                        dict[kv.Key] = kv.Value; // POST 優先
                }
            }

            // 再讀 Query，只有當 POST 沒給時才補
            var query = req.Url.Query; // 例如 "?pwd=abc&cmd=default"
            if (!string.IsNullOrEmpty(query) && query.Length > 1)
            {
                foreach (var kv in ParseFormUrlEncoded(query.Substring(1)))
                {
                    if (!dict.ContainsKey(kv.Key))
                        dict[kv.Key] = kv.Value;
                }
            }

            return dict;
        }

    }
}
