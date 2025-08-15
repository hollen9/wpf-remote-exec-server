using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Windows;
using Microsoft.Win32;
using wpf_remoteexec.Helpers;
using IOPath = System.IO.Path;

namespace wpf_remoteexec
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    [DataContract]
    public class CommandItem : INotifyPropertyChanged
    {
        string _name;
        string _filePath;
        string _arguments;
        bool _enabled;
        int? _timeoutMs;          // null = 使用 Global
        bool _noResponse;         // 勾選時 fire-and-forget
        bool _hideWindow;         // 勾選時隱藏視窗（預設不勾）

        [DataMember] public string Name { get { return _name; } set { if (_name != value) { _name = value; OnPropertyChanged("Name"); } } }
        [DataMember] public string FilePath { get { return _filePath; } set { if (_filePath != value) { _filePath = value; OnPropertyChanged("FilePath"); } } }
        [DataMember] public string Arguments { get { return _arguments; } set { if (_arguments != value) { _arguments = value; OnPropertyChanged("Arguments"); } } }
        [DataMember] public bool Enabled { get { return _enabled; } set { if (_enabled != value) { _enabled = value; OnPropertyChanged("Enabled"); } } }

        [DataMember] public int? TimeoutMs { get { return _timeoutMs; } set { if (_timeoutMs != value) { _timeoutMs = value; OnPropertyChanged("TimeoutMs"); } } }
        [DataMember] public bool NoResponse { get { return _noResponse; } set { if (_noResponse != value) { _noResponse = value; OnPropertyChanged("NoResponse"); } } }
        [DataMember] public bool HideWindow { get { return _hideWindow; } set { if (_hideWindow != value) { _hideWindow = value; OnPropertyChanged("HideWindow"); } } }

        public event PropertyChangedEventHandler PropertyChanged;
        void OnPropertyChanged(string propertyName)
        {
            var handler = PropertyChanged;
            if (handler != null)
                handler(this, new PropertyChangedEventArgs(propertyName));
        }

    }

    [DataContract]
    public class AppSettings
    {
        [DataMember] public int Port { get; set; }
        [DataMember] public string Password { get; set; }
        [DataMember] public bool PostOnly { get; set; }
        [DataMember] public bool Same24 { get; set; }
        [DataMember] public int GlobalTimeoutMs { get; set; } // 0 或 負數 = 不做逾時
    }

    public partial class MainWindow : Window
    {
        // --- Auto-start options (from command line) ---
        bool _autoStart = false;                 // --autostart
        bool _autoStartSkipChecks = false;       // --autostart:force  (跳過沒有啟用指令的確認)
        bool _startMinimized = false;            // --minimized


        // ===== Runtime snapshot for worker threads =====
        volatile bool _optPostOnly;
        volatile bool _optSame24;
        string _optPassword;
        int _optGlobalTimeoutMs;

        List<CommandItem> _cmdSnapshot = new List<CommandItem>();

        // ===== HTTP / files =====
        HttpListener _listener;
        volatile bool _running;
        string _prefix;
        readonly string _routeRun = "/run";
        readonly string _routeList = "/list";

        readonly string _logFile = @"C:\scripts\bat-trigger.log";
        readonly string _cmdFile = "commands.json";
        readonly string _settingsFile = "settings.json";

        List<IPAddress> _localIPv4s = new List<IPAddress>();
        public ObservableCollection<CommandItem> Commands { get; private set; }
        AppSettings _settings;

        readonly object _cmdLock = new object();

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;
            Commands = new ObservableCollection<CommandItem>();

            LoadSettings();     // 先載設定（Port/Password/Timeout 等）
            LoadCommands();     // 再載指令

            // Arg Start
            ParseCmdArgs();

            if (_startMinimized)
                this.WindowState = WindowState.Minimized;

            // 等視窗載入完再按「Start」
            this.Loaded += (s, e) =>
            {
                if (_autoStart)
                    StartBtn_Click(null, new RoutedEventArgs());
            };
            // Arg Ended

            Append("Ready. Loaded commands: " + Commands.Count);
        }

        private void ParseCmdArgs()
        {
            try
            {
                var args = Environment.GetCommandLineArgs();
                for (int i = 1; i < args.Length; i++)
                {
                    var raw = args[i];
                    var a = raw.TrimStart('-', '/').ToLowerInvariant();

                    if (a == "autostart")
                    {
                        _autoStart = true;
                    }
                    else if (a == "autostart:force" || a == "autostart=force")
                    {
                        _autoStart = true;
                        _autoStartSkipChecks = true;
                    }
                    else if (a == "minimized" || a == "minimize" || a == "minimise")
                    {
                        _startMinimized = true;
                    }
                }
            }
            catch { }
        }

        // ===== Settings persistence =====

        void LoadSettings()
        {
            try
            {
                if (File.Exists(_settingsFile))
                {
                    using (var fs = File.OpenRead(_settingsFile))
                    {
                        var ser = new DataContractJsonSerializer(typeof(AppSettings));
                        _settings = (AppSettings)ser.ReadObject(fs);
                    }
                }
            }
            catch (Exception ex)
            {
                Append("LoadSettings ERROR: " + ex.Message);
            }

            if (_settings == null)
            {
                _settings = new AppSettings
                {
                    Port = 8087,
                    Password = "ChangeThisPassword!",
                    PostOnly = false,
                    Same24 = true,
                    GlobalTimeoutMs = 15000
                };
                SaveSettings(); // 產生預設
            }

            // 套到 UI
            PortBox.Text = _settings.Port.ToString();
            PwdBox.Password = _settings.Password ?? "";
            PostOnlyChk.IsChecked = _settings.PostOnly;
            Same24Chk.IsChecked = _settings.Same24;
            GlobalTimeoutBox.Text = _settings.GlobalTimeoutMs.ToString();
        }

        void SaveSettings()
        {
            try
            {
                // 從 UI 回存
                int port;
                if (!int.TryParse(PortBox.Text.Trim(), out port)) port = 8087;
                int gto;
                if (!int.TryParse(GlobalTimeoutBox.Text.Trim(), out gto)) gto = 15000;

                _settings.Port = port;
                _settings.Password = PwdBox.Password ?? "";
                _settings.PostOnly = (PostOnlyChk.IsChecked == true);
                _settings.Same24 = (Same24Chk.IsChecked == true);
                _settings.GlobalTimeoutMs = gto;

                using (var fs = File.Create(_settingsFile))
                {
                    var ser = new DataContractJsonSerializer(typeof(AppSettings));
                    ser.WriteObject(fs, _settings);
                }
                Append("Settings saved.");
            }
            catch (Exception ex)
            {
                Append("SaveSettings ERROR: " + ex.Message);
            }
        }

        // ===== UI: Start/Stop =====

        private void StartBtn_Click(object sender, RoutedEventArgs e)
        {
            // 先保存一次設定，確保 UI 值落地並且快照使用最新
            SaveSettings();

            int port = _settings.Port;
            if (port <= 0 || port > 65535)
            {
                MessageBox.Show("Invalid port.");
                return;
            }
            if (string.IsNullOrEmpty(_settings.Password))
            {
                MessageBox.Show("Set a password.");
                return;
            }
            if (!Commands.Any(c => c.Enabled))
            {
                if (!_autoStartSkipChecks)
                {
                    if (MessageBox.Show("No enabled commands. Start anyway?", "Confirm",
                        MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                        return;
                }
                // autoStartSkipChecks = true 時不跳對話框，直接啟動
            }

            _localIPv4s = GetLocalIPv4s();
            Append("Local IPv4(s): " + string.Join(", ", _localIPv4s.Select(ip => ip.ToString()).ToArray()));

            _prefix = "http://+:" + port + "/";
            _listener = new HttpListener();
            _listener.Prefixes.Add(_prefix);

            // Snapshot for worker
            _optPostOnly = _settings.PostOnly;
            _optSame24 = _settings.Same24;
            _optPassword = _settings.Password;
            _optGlobalTimeoutMs = _settings.GlobalTimeoutMs;

            lock (_cmdLock) { _cmdSnapshot = new List<CommandItem>(Commands); }

            try { _listener.Start(); }
            catch (Exception ex)
            {
                Append("HttpListener start FAILED: " + ex.Message);
                MessageBox.Show("HttpListener 無法啟動（請用系統管理員執行，或改用具體 IP 前綴）。\n\n" + ex.Message);
                _listener = null;
                return;
            }

            _running = true;
            ThreadPool.QueueUserWorkItem(ServerLoop);
            StartBtn.IsEnabled = false;
            StopBtn.IsEnabled = true;
            Append("Server started: " + _prefix + " routes: " + _routeRun + ", " + _routeList);
        }

        private void StopBtn_Click(object sender, RoutedEventArgs e)
        {
            StopServer();
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            StopServer();
        }

        void StopServer()
        {
            _running = false;
            try { if (_listener != null) _listener.Stop(); } catch { }
            try { if (_listener != null) _listener.Close(); } catch { }
            _listener = null;
            StartBtn.IsEnabled = true;
            StopBtn.IsEnabled = false;
            Append("Server stopped.");
        }

        // ===== HTTP Loop =====

        void ServerLoop(object state)
        {
            while (_running && _listener != null && _listener.IsListening)
            {
                HttpListenerContext ctx = null;
                try { ctx = _listener.GetContext(); }
                catch { if (!_running) break; continue; }
                ThreadPool.QueueUserWorkItem(HandleRequest, ctx);
            }
        }

        void HandleRequest(object state)
        {
            var ctx = (HttpListenerContext)state;
            var req = ctx.Request;
            var resp = ctx.Response;

            var remoteIp = req.RemoteEndPoint != null ? req.RemoteEndPoint.Address : null;
            var remoteStr = remoteIp != null ? remoteIp.ToString() : req.UserHostAddress;

            try
            {
                var path = req.Url.AbsolutePath;

                if (_optPostOnly && !req.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
                {
                    Write(resp, 405, "Method Not Allowed");
                    return;
                }

                if (_optSame24)
                {
                    if (remoteIp == null || (!IPAddress.IsLoopback(remoteIp) && !_IsSame24AsAnyLocal(remoteIp)))
                    {
                        Append("DENY by /24: " + remoteStr);
                        Write(resp, 403, "Forbidden");
                        return;
                    }
                }

                if (path.Equals(_routeRun, StringComparison.OrdinalIgnoreCase))
                {
                    HandleRun(req, resp, remoteStr);
                    return;
                }
                else if (path.Equals(_routeList, StringComparison.OrdinalIgnoreCase))
                {
                    HandleList(req, resp);
                    return;
                }
                else
                {
                    Write(resp, 404, "Not Found");
                    return;
                }
            }
            catch (Exception ex)
            {
                Append("Handle ERROR: " + ex.Message);
                SafeWrite(resp, 500, "Internal Error");
            }
            finally
            {
                try { resp.OutputStream.Close(); } catch { }
            }
        }

        // ===== Handlers =====

        void HandleRun(HttpListenerRequest req, HttpListenerResponse resp, string remoteStr)
        {
            // 讀欄位（POST 表單 + Query）
            var fields = ReadFields(req);
            string pwd = null, cmdName = null;
            fields.TryGetValue("pwd", out pwd);
            fields.TryGetValue("cmd", out cmdName);

            if (string.IsNullOrEmpty(pwd) || !SlowEquals(pwd, _optPassword))
            {
                Append("Wrong password from " + remoteStr);
                Write(resp, 401, "Unauthorized");
                return;
            }
            if (string.IsNullOrEmpty(cmdName))
            {
                Write(resp, 400, "Bad Request: missing 'cmd'");
                return;
            }

            CommandItem item = null;
            lock (_cmdLock)
            {
                item = _cmdSnapshot.FirstOrDefault(c =>
                    c.Enabled && !string.IsNullOrEmpty(c.Name) &&
                    c.Name.Equals(cmdName, StringComparison.OrdinalIgnoreCase));
            }

            if (item == null)
            {
                Write(resp, 404, "Command not found or disabled: " + cmdName);
                return;
            }
            if (string.IsNullOrEmpty(item.FilePath) || !File.Exists(item.FilePath))
            {
                Write(resp, 500, "Command file not found: " + item.FilePath);
                return;
            }

            // 決定模式與逾時/視窗選項
            int effectiveTimeout = (item.TimeoutMs.HasValue ? item.TimeoutMs.Value : _optGlobalTimeoutMs);
            bool noResponse = item.NoResponse;
            bool hideWindow = item.HideWindow;

            if (noResponse)
            {
                StartDetached(item.FilePath, item.Arguments ?? "", hideWindow);
                Append("RUN FIRE '" + item.Name + "' (detached) from " + remoteStr);
                Write(resp, 202, "Accepted (detached)");
                return;
            }

            string stdOut, stdErr;
            int exitCode;
            bool ok = RunExecWithTimeout(item.FilePath, item.Arguments ?? "", effectiveTimeout, hideWindow,
                                         out stdOut, out stdErr, out exitCode);

            if (ok)
            {
                Append("RUN OK '" + item.Name + "' from " + remoteStr + " (Exit " + exitCode + ")");
                Write(resp, 200, "OK\nCommand=" + item.Name + "\nExitCode=" + exitCode + "\n" + stdOut);
            }
            else
            {
                Append("RUN FAILED '" + item.Name + "' from " + remoteStr + " (Exit " + exitCode + ")\n" + stdErr);
                Write(resp, 500, "FAILED\nCommand=" + item.Name + "\nExitCode=" + exitCode + "\n" + stdErr);
            }
        }

        void HandleList(HttpListenerRequest req, HttpListenerResponse resp)
        {
            List<string> names;
            lock (_cmdLock)
            {
                names = _cmdSnapshot.Where(c => c.Enabled && !string.IsNullOrEmpty(c.Name))
                                    .Select(c => c.Name)
                                    .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                                    .ToList();
            }
            var sb = new StringBuilder();
            foreach (var n in names) sb.AppendLine(n);
            Write(resp, 200, sb.ToString());
        }

        // ===== Exec helpers =====

        void StartDetached(string filePath, string arguments, bool hideWindow)
        {
            // 用 cmd /c 相容 .bat / .cmd / .exe（exe 會把引號當參數傳遞沒問題）
            string quoted = "\"" + filePath + "\"";
            var psi = new ProcessStartInfo("cmd.exe", "/c " + quoted + (string.IsNullOrEmpty(arguments) ? "" : " " + arguments))
            {
                WorkingDirectory = SafeDirOf(filePath)
            };

            if (hideWindow)
            {
                psi.UseShellExecute = true;     // 不能重定向，才好隱藏
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
            }
            else
            {
                // 讓使用者可看到窗口（若是 console app）
                psi.UseShellExecute = true;
                psi.CreateNoWindow = false;
                psi.WindowStyle = ProcessWindowStyle.Normal;
            }

            Process.Start(psi);
        }

        bool RunExecWithTimeout(string filePath, string arguments, int timeoutMs, bool hideWindow,
                                out string stdOut, out string stdErr, out int exitCode)
        {
            stdOut = ""; stdErr = ""; exitCode = -1;

            var psi = new ProcessStartInfo
            {
                FileName = filePath,
                Arguments = arguments ?? "",
                WorkingDirectory = SafeDirOf(filePath)
            };

            // 若要拿到輸出，就不能 UseShellExecute=true；此時 Hide 交由 CreateNoWindow 控制
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = hideWindow; // 勾選才隱藏；預設 false = 會有視窗（若為 console）

            try
            {
                using (var p = new Process())
                {
                    p.StartInfo = psi;
                    p.Start();

                    if (timeoutMs > 0)
                    {
                        if (!p.WaitForExit(timeoutMs))
                        {
                            try { p.Kill(); } catch { }
                            exitCode = -9999;
                            stdOut = p.StandardOutput.ReadToEnd();
                            stdErr = "[Timeout] " + p.StandardError.ReadToEnd();
                            return false;
                        }
                    }
                    else
                    {
                        p.WaitForExit();
                    }

                    stdOut = p.StandardOutput.ReadToEnd();
                    stdErr = p.StandardError.ReadToEnd();
                    exitCode = p.ExitCode;
                    return exitCode == 0;
                }
            }
            catch (Exception ex)
            {
                stdErr = ex.Message;
                return false;
            }
        }

        string SafeDirOf(string path)
        {
            try { return IOPath.GetDirectoryName(path) ?? AppDomain.CurrentDomain.BaseDirectory; }
            catch { return AppDomain.CurrentDomain.BaseDirectory; }
        }

        // ===== Networking helpers =====

        List<IPAddress> GetLocalIPv4s()
        {
            var list = new List<IPAddress>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    var props = ni.GetIPProperties();
                    foreach (var ua in props.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            var b = ua.Address.GetAddressBytes();
                            if (b[0] == 169 || b[0] == 127) continue;
                            list.Add(ua.Address);
                        }
                    }
                }
            }
            catch { }
            if (list.Count == 0)
            {
                IPAddress ip;
                if (IPAddress.TryParse("127.0.0.1", out ip)) list.Add(ip);
            }
            return list;
        }

        bool _IsSame24AsAnyLocal(IPAddress remote)
        {
            if (remote.AddressFamily != AddressFamily.InterNetwork) return false;
            var rb = remote.GetAddressBytes();
            foreach (var ip in _localIPv4s)
            {
                var lb = ip.GetAddressBytes();
                if (lb[0] == rb[0] && lb[1] == rb[1] && lb[2] == rb[2])
                    return true;
            }
            return false;
        }

        // ===== Field parsing (POST form + Query) =====

        Dictionary<string, string> ReadFields(HttpListenerRequest req)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if ("POST".Equals(req.HttpMethod, StringComparison.OrdinalIgnoreCase) &&
                req.HasEntityBody &&
                req.ContentType != null &&
                req.ContentType.IndexOf("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                using (var sr = new StreamReader(req.InputStream, req.ContentEncoding ?? Encoding.UTF8))
                {
                    var body = sr.ReadToEnd();
                    foreach (var kv in ParseFormUrlEncoded(body)) dict[kv.Key] = kv.Value;
                }
            }

            var query = req.Url.Query;
            if (!string.IsNullOrEmpty(query) && query.Length > 1)
            {
                foreach (var kv in ParseFormUrlEncoded(query.Substring(1)))
                    if (!dict.ContainsKey(kv.Key)) dict[kv.Key] = kv.Value;
            }

            return dict;
        }

        static Dictionary<string, string> ParseFormUrlEncoded(string s)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(s)) return dict;

            var pairs = s.Split('&');
            foreach (var p in pairs)
            {
                var kv = p.Split(new[] { '=' }, 2);
                var key = UrlDecodePlus(kv[0]);
                var val = kv.Length > 1 ? UrlDecodePlus(kv[1]) : "";
                dict[key] = val;
            }
            return dict;
        }

        static string UrlDecodePlus(string s)
        {
            if (s == null) return "";
            return Uri.UnescapeDataString(s.Replace("+", " "));
        }

        static bool SlowEquals(string a, string b)
        {
            if (a == null || b == null) return false;
            int diff = a.Length ^ b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        // ===== UI: Commands =====

        void AddCmd_Click(object sender, RoutedEventArgs e)
        {
            var item = new CommandItem
            {
                Name = "NewCommand",
                FilePath = @"C:\scripts\myjob.bat",
                Arguments = "",
                Enabled = true,
                TimeoutMs = null,     // 用 Global
                NoResponse = false,   // 預設要回應
                HideWindow = false    // 預設不隱藏
            };
            Commands.Add(item);
        }

        void RemoveCmd_Click(object sender, RoutedEventArgs e)
        {
            var sel = CmdGrid.SelectedItem as CommandItem;
            if (sel != null) Commands.Remove(sel);
        }

        void SaveCmd_Click(object sender, RoutedEventArgs e)
        {
            SaveCommands();
            lock (_cmdLock) { _cmdSnapshot = new List<CommandItem>(Commands); }
            Append("Command snapshot updated.");
            // 同步保存最新 Settings（避免只改了 Global Timeout/Port 但沒按 Start）
            SaveSettings();
        }

        void BrowseRow_Click(object sender, RoutedEventArgs e)
        {
            CmdGrid.CommitEdit(System.Windows.Controls.DataGridEditingUnit.Cell, true);
            CmdGrid.CommitEdit(System.Windows.Controls.DataGridEditingUnit.Row, true);

            var btn = sender as System.Windows.Controls.Button;
            var item = btn != null ? btn.Tag as CommandItem : null;
            if (item == null) return;

            var dlg = new OpenFileDialog();
            dlg.Filter = "Executable / Batch (*.exe;*.bat;*.cmd)|*.exe;*.bat;*.cmd|All files (*.*)|*.*";
            if (dlg.ShowDialog() == true)
            {
                item.FilePath = dlg.FileName; // INotifyPropertyChanged 會更新 UI
            }
        }

        void LoadCommands()
        {
            try
            {
                if (!File.Exists(_cmdFile))
                {
                    Commands.Add(new CommandItem
                    {
                        Name = "default",
                        FilePath = @"C:\scripts\myjob.bat",
                        Arguments = "",
                        Enabled = true,
                        TimeoutMs = null,     // 使用 Global
                        NoResponse = false,
                        HideWindow = false
                    });
                    SaveCommands();
                    return;
                }

                using (var fs = File.OpenRead(_cmdFile))
                {
                    var ser = new DataContractJsonSerializer(typeof(List<CommandItem>));
                    var list = (List<CommandItem>)ser.ReadObject(fs);
                    Commands.Clear();
                    foreach (var c in list) Commands.Add(c);
                }
            }
            catch (Exception ex)
            {
                Append("LoadCommands ERROR: " + ex.Message);
            }
        }

        void SaveCommands()
        {
            try
            {
                var list = new List<CommandItem>(Commands);
                using (var fs = File.Create(_cmdFile))
                {
                    var ser = new DataContractJsonSerializer(typeof(List<CommandItem>));
                    ser.WriteObject(fs, list);
                }
                Append("Commands saved (" + list.Count + ").");
            }
            catch (Exception ex)
            {
                Append("SaveCommands ERROR: " + ex.Message);
            }
        }

        // ===== Logging & HTTP write =====

        void Append(string line)
        {
            var msg = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + line + Environment.NewLine;

            // 顯示到 UI
            Dispatcher.Invoke((Action)(() =>
            {
                LogBox.AppendText(msg);
                LogBox.ScrollToEnd();
            }));

            try
            {
                // 建立 .log 資料夾
                var logDir = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, ".log");
                Directory.CreateDirectory(logDir);

                // 每日一檔
                var logPath = IOPath.Combine(logDir, DateTime.Now.ToString("yyyy-MM-dd") + ".log");
                File.AppendAllText(logPath, msg, Encoding.UTF8);
            }
            catch { }
        }

        void Write(HttpListenerResponse resp, int status, string text)
        {
            resp.StatusCode = status;
            resp.ContentType = "text/plain; charset=utf-8";
            var buf = Encoding.UTF8.GetBytes(text ?? "");
            resp.ContentLength64 = buf.Length; // 明確宣告，避免某些客戶端等待
            resp.OutputStream.Write(buf, 0, buf.Length);
        }

        void SafeWrite(HttpListenerResponse resp, int status, string text)
        {
            try { Write(resp, status, text); } catch { }
        }
    }
}
