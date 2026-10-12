// 公開前チェック（koukai-check）の専用ウィンドウ（Windows）。
//
// 役割：Node.js 側（koukai-check.exe）が 127.0.0.1 で動かしている画面を、Microsoft Edge WebView2 で
// 「公開前チェック」という名前のウィンドウの中に表示する。アドレスバー・タブ・開発者ツールはない。
//
// 安全のための方針：
//   ・表示してよいのは、Node.js 側から最初に渡された http://127.0.0.1:<port>/r/<乱数>/ で始まるページだけ。
//     それ以外への移動はすべて止める。https のリンクは、Node.js 側が許可したものだけ既定のブラウザで開く。
//   ・ページの JavaScript からこのプログラムの機能を呼べる仕組み（host object / web message）は使わない。
//   ・開発者ツール・ブラウザのショートカットキー・右クリックメニュー（コピー・貼り付け以外）・
//     ファイルのドロップ・通知などの許可要求・パスワードの保存・自動入力は無効にする。
//   ・閲覧データを残さない InPrivate モードで表示する（対応していない古いランタイムでは通常モード）。
//
// Node.js 側との通信は、標準入出力の1行ずつのテキスト（UTF-8）で行う：
//   Node.js → ここ： NAVIGATE <url> / PICK / OPEN-EXTERNAL <url> / QUIT
//   ここ → Node.js： READY / PICKED <path> / PICK-CANCELLED / PICK-FAILED / EXTERNAL <url> / NO-RUNTIME / FAILED <code> / CLOSED
// 標準入力が閉じられたら（Node.js 側が終了したら）、ウィンドウも閉じる。
//
// もう一つの使い方：`koukai-check-window.exe --fatal` は、標準入力で受け取った文章をエラーとして表示するだけ。

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
// 対象は Windows 10 以降（GetDpiForWindow などを使う）。MinGW-w64 の配布によって既定値が違うため明示する
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0A00
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <functional>
#include <set>
#include <string>
#include <thread>
#include <utility>

#include "WebView2.h"

namespace {

const wchar_t kTitle[] = L"公開前チェック";
const wchar_t kWindowClass[] = L"KoukaiCheckWindow";
const wchar_t kRuntimePage[] = L"https://developer.microsoft.com/microsoft-edge/webview2/";
constexpr UINT WM_APP_LINE = WM_APP + 1;          // lParam: std::string*（Node.js から届いた1行）
constexpr UINT WM_APP_STDIN_CLOSED = WM_APP + 2;
constexpr UINT WM_APP_DOWNLOAD = WM_APP + 3;      // lParam: PendingDownload*
constexpr size_t kMaxLine = 16 * 1024;

// ───────────── 文字コード ─────────────

std::wstring FromUtf8(const std::string& s) {
  if (s.empty()) return L"";
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
  if (n <= 0) return L"";
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), &w[0], n);
  return w;
}

std::string ToUtf8(const std::wstring& w) {
  if (w.empty()) return "";
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  if (n <= 0) return "";
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
  return s;
}

/** CoTaskMemAlloc された文字列を受け取って解放する */
std::wstring TakeCoString(LPWSTR p) {
  std::wstring s = p ? p : L"";
  if (p) CoTaskMemFree(p);
  return s;
}

bool StartsWith(const std::wstring& s, const std::wstring& prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

// ───────────── Node.js との通信 ─────────────

HANDLE g_out = INVALID_HANDLE_VALUE;

void Send(const std::string& line) {
  if (g_out == INVALID_HANDLE_VALUE) return;
  std::string clean;
  for (char c : line) clean.push_back(c == '\r' || c == '\n' ? ' ' : c);  // 改行を混ぜない
  clean.push_back('\n');
  DWORD written = 0;
  WriteFile(g_out, clean.data(), (DWORD)clean.size(), &written, nullptr);
}

bool ReadLineBlocking(HANDLE in, std::string& line) {
  line.clear();
  char c;
  DWORD n = 0;
  while (ReadFile(in, &c, 1, &n, nullptr) && n == 1) {
    if (c == '\n') return true;
    if (c != '\r' && line.size() < kMaxLine) line.push_back(c);
  }
  return false;
}

// ───────────── COM のコールバック ─────────────

template <typename I, typename... Args>
class Callback : public I {
 public:
  Callback(REFIID iid, std::function<HRESULT(Args...)> fn) : iid_(iid), fn_(std::move(fn)) {}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, iid_)) {
      *ppv = static_cast<I*>(this);
      AddRef();
      return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return (ULONG)InterlockedIncrement(&ref_); }
  ULONG STDMETHODCALLTYPE Release() override {
    LONG r = InterlockedDecrement(&ref_);
    if (r == 0) delete this;
    return (ULONG)r;
  }
  HRESULT STDMETHODCALLTYPE Invoke(Args... args) override { return fn_(args...); }

 private:
  virtual ~Callback() = default;
  LONG ref_ = 1;
  IID iid_;
  std::function<HRESULT(Args...)> fn_;
};

template <typename T>
void SafeRelease(T*& p) {
  if (p) {
    p->Release();
    p = nullptr;
  }
}

// ───────────── アプリ本体 ─────────────

struct PendingDownload {
  ICoreWebView2DownloadStartingEventArgs* args;
  ICoreWebView2Deferral* deferral;
};

class App {
 public:
  bool Init(HINSTANCE inst, const std::wstring& url);
  void OnLine(const std::string& line);
  LRESULT WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
  HWND hwnd() const { return hwnd_; }

 private:
  bool LoadLoader();
  void CreateWebView();
  void OnController(ICoreWebView2Controller* controller);
  void ApplySettings();
  void AddEventHandlers();
  bool IsAppUrl(const std::wstring& uri) const { return StartsWith(uri, prefix_); }
  void RequestExternal(const std::wstring& uri);
  void PickFolder();
  void ShowDownloadDialog(PendingDownload* pending);
  void Resize();
  void BringToFront();
  void Fail(HRESULT hr, const wchar_t* what);
  void NoRuntime();

  HWND hwnd_ = nullptr;
  std::wstring url_;
  std::wstring prefix_;
  HMODULE loader_ = nullptr;
  ICoreWebView2Environment* env_ = nullptr;
  ICoreWebView2Controller* controller_ = nullptr;
  ICoreWebView2* webview_ = nullptr;
  IFileDialog* openDialog_ = nullptr;  // フォルダ選択中だけ設定される
  bool picking_ = false;
  bool closing_ = false;
  bool ready_ = false;
};

App g_app;

LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) { return g_app.WndProc(hwnd, msg, wp, lp); }

std::wstring ModuleDir() {
  wchar_t buf[MAX_PATH * 4];
  DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
  std::wstring path(buf, n);
  size_t slash = path.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"." : path.substr(0, slash);
}

std::wstring UserDataFolder() {
  PWSTR local = nullptr;
  std::wstring dir;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local)) && local) {
    dir = std::wstring(local) + L"\\koukai-check\\WebView2";
  }
  if (local) CoTaskMemFree(local);
  return dir;
}

typedef HRESULT(STDAPICALLTYPE* CreateEnvFn)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);
typedef HRESULT(STDAPICALLTYPE* VersionFn)(PCWSTR, LPWSTR*);

bool App::Init(HINSTANCE inst, const std::wstring& url) {
  url_ = url;
  prefix_ = url;  // 例：http://127.0.0.1:51234/r/0123…/

  WNDCLASSEXW wc = {};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = StaticWndProc;
  wc.hInstance = inst;
  wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
  wc.hIconSm = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hbrBackground = CreateSolidBrush(RGB(0xf6, 0xf7, 0xf9));
  wc.lpszClassName = kWindowClass;
  if (!RegisterClassExW(&wc)) return false;

  // 画面の大きさに合わせて、作業領域の中央に置く
  RECT work = {0, 0, 1280, 800};
  SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
  UINT dpi = GetDpiForSystem();
  int w = MulDiv(1080, (int)dpi, 96), h = MulDiv(820, (int)dpi, 96);
  int ww = work.right - work.left, wh = work.bottom - work.top;
  if (w > ww - 40) w = ww - 40;
  if (h > wh - 40) h = wh - 40;
  int x = work.left + (ww - w) / 2, y = work.top + (wh - h) / 2;

  hwnd_ = CreateWindowExW(0, kWindowClass, kTitle, WS_OVERLAPPEDWINDOW, x, y, w, h, nullptr, nullptr, inst, nullptr);
  if (!hwnd_) return false;
  ShowWindow(hwnd_, SW_SHOWNORMAL);
  UpdateWindow(hwnd_);
  BringToFront();

  if (!LoadLoader()) {
#ifdef KC_SMOKE_TEST
    // 動作確認用のビルドだけ（配布物には含めない）：WebView2 がない環境（wine など）でも、
    // Node.js 側との通信を確かめられるようにする。表示する URL を KC_SMOKE_URL_FILE に書き出す
    wchar_t file[MAX_PATH];
    if (GetEnvironmentVariableW(L"KC_SMOKE_URL_FILE", file, MAX_PATH)) {
      HANDLE f = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      std::string u = ToUtf8(url_);
      DWORD w = 0;
      if (f != INVALID_HANDLE_VALUE) WriteFile(f, u.data(), (DWORD)u.size(), &w, nullptr), CloseHandle(f);
    }
    Send("READY");
    return true;
#endif
    NoRuntime();
    return true;
  }
  CreateWebView();
  return true;
}

void App::BringToFront() {
  if (IsIconic(hwnd_)) ShowWindow(hwnd_, SW_RESTORE);
  // 他のウィンドウの裏に隠れないよう、一度だけ最前面にしてから戻す（ずっと最前面にはしない）
  SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
  SetWindowPos(hwnd_, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
  SetForegroundWindow(hwnd_);
  if (GetForegroundWindow() != hwnd_) {
    FLASHWINFO fi = {sizeof(fi), hwnd_, FLASHW_ALL | FLASHW_TIMERNOFG, 0, 0};
    FlashWindowEx(&fi);
  }
}

bool App::LoadLoader() {
  // Microsoft 公式の WebView2Loader.dll（このプログラムと同じフォルダに置かれたもの）だけを読み込む
  std::wstring path = ModuleDir() + L"\\WebView2Loader.dll";
  loader_ = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!loader_) return false;
  auto version = reinterpret_cast<VersionFn>(reinterpret_cast<void*>(GetProcAddress(loader_, "GetAvailableCoreWebView2BrowserVersionString")));
  if (!version) return false;
  LPWSTR v = nullptr;
  HRESULT hr = version(nullptr, &v);
  std::wstring ver = TakeCoString(v);
  return SUCCEEDED(hr) && !ver.empty();
}

void App::CreateWebView() {
  auto create = reinterpret_cast<CreateEnvFn>(reinterpret_cast<void*>(GetProcAddress(loader_, "CreateCoreWebView2EnvironmentWithOptions")));
  if (!create) return NoRuntime();
  std::wstring data = UserDataFolder();
  auto* cb = new Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler, HRESULT, ICoreWebView2Environment*>(
      IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler, [this](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
        if (FAILED(hr) || !env) {
          Fail(hr, L"WebView2 の準備");
          return S_OK;
        }
        env_ = env;
        env_->AddRef();
        auto* done = new Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler, HRESULT, ICoreWebView2Controller*>(
            IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler, [this](HRESULT hr2, ICoreWebView2Controller* c) -> HRESULT {
              if (FAILED(hr2) || !c) Fail(hr2, L"画面の作成");
              else OnController(c);
              return S_OK;
            });
        // 閲覧データ（キャッシュなど）をディスクに残さない InPrivate モードで作る
        ICoreWebView2Environment10* env10 = nullptr;
        ICoreWebView2ControllerOptions* options = nullptr;
        HRESULT r = E_NOINTERFACE;
        if (SUCCEEDED(env_->QueryInterface(IID_ICoreWebView2Environment10, (void**)&env10)) && env10 &&
            SUCCEEDED(env10->CreateCoreWebView2ControllerOptions(&options)) && options) {
          options->put_IsInPrivateModeEnabled(TRUE);
          r = env10->CreateCoreWebView2ControllerWithOptions(hwnd_, options, done);
        }
        if (FAILED(r)) r = env_->CreateCoreWebView2Controller(hwnd_, done);
        SafeRelease(options);
        SafeRelease(env10);
        done->Release();
        if (FAILED(r)) Fail(r, L"画面の作成");
        return S_OK;
      });
  HRESULT hr = create(nullptr, data.empty() ? nullptr : data.c_str(), nullptr, cb);
  cb->Release();
  if (FAILED(hr)) {
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) NoRuntime();
    else Fail(hr, L"WebView2 の準備");
  }
}

void App::OnController(ICoreWebView2Controller* controller) {
  if (closing_) return;
  controller_ = controller;
  controller_->AddRef();
  if (FAILED(controller_->get_CoreWebView2(&webview_)) || !webview_) return Fail(E_FAIL, L"画面の作成");
  ApplySettings();
  AddEventHandlers();
  Resize();
  webview_->Navigate(url_.c_str());
  controller_->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
  ready_ = true;
  Send("READY");
}

void App::ApplySettings() {
  ICoreWebView2Settings* s = nullptr;
  if (FAILED(webview_->get_Settings(&s)) || !s) return;
  s->put_AreDevToolsEnabled(FALSE);
  s->put_IsStatusBarEnabled(FALSE);
  s->put_AreHostObjectsAllowed(FALSE);
  s->put_IsWebMessageEnabled(FALSE);
  s->put_IsScriptEnabled(TRUE);  // コピーのボタンと「処理中」の表示に使う
  s->put_AreDefaultScriptDialogsEnabled(TRUE);
  s->put_IsZoomControlEnabled(TRUE);  // Ctrl + マウスホイールでの拡大は残す（読みやすさのため）
  s->put_IsBuiltInErrorPageEnabled(TRUE);

  ICoreWebView2_11* w11 = nullptr;
  if (FAILED(webview_->QueryInterface(IID_ICoreWebView2_11, (void**)&w11)) || !w11) {
    // 右クリックメニューを絞り込めない古いランタイムでは、右クリックメニューそのものを出さない
    s->put_AreDefaultContextMenusEnabled(FALSE);
  }
  SafeRelease(w11);

  ICoreWebView2Settings3* s3 = nullptr;
  if (SUCCEEDED(s->QueryInterface(IID_ICoreWebView2Settings3, (void**)&s3)) && s3) {
    // F5・Ctrl+P・Ctrl+F・F12・Alt+← などのブラウザ用ショートカットを無効にする（コピー・貼り付けなどの編集操作は使える）
    s3->put_AreBrowserAcceleratorKeysEnabled(FALSE);
  }
  SafeRelease(s3);
  ICoreWebView2Settings4* s4 = nullptr;
  if (SUCCEEDED(s->QueryInterface(IID_ICoreWebView2Settings4, (void**)&s4)) && s4) {
    s4->put_IsPasswordAutosaveEnabled(FALSE);  // トークンの欄を「パスワードとして保存」させない
    s4->put_IsGeneralAutofillEnabled(FALSE);
  }
  SafeRelease(s4);
  ICoreWebView2Settings6* s6 = nullptr;
  if (SUCCEEDED(s->QueryInterface(IID_ICoreWebView2Settings6, (void**)&s6)) && s6) s6->put_IsSwipeNavigationEnabled(FALSE);
  SafeRelease(s6);
  ICoreWebView2Settings8* s8 = nullptr;
  if (SUCCEEDED(s->QueryInterface(IID_ICoreWebView2Settings8, (void**)&s8)) && s8) {
    // 表示するのは 127.0.0.1 のページだけなので、URL の評価（SmartScreen）を問い合わせない
    s8->put_IsReputationCheckingRequired(FALSE);
  }
  SafeRelease(s8);
  s->Release();

  ICoreWebView2Controller4* c4 = nullptr;
  if (SUCCEEDED(controller_->QueryInterface(IID_ICoreWebView2Controller4, (void**)&c4)) && c4) {
    c4->put_AllowExternalDrop(FALSE);  // ファイルをドロップしてページが切り替わるのを防ぐ
  }
  SafeRelease(c4);
}

void App::RequestExternal(const std::wstring& uri) {
  // 既定のブラウザで開くかどうかは Node.js 側が判定する（許可されたら OPEN-EXTERNAL が返ってくる）
  if (StartsWith(uri, L"https://") && uri.size() <= 2048) Send("EXTERNAL " + ToUtf8(uri));
}

void App::AddEventHandlers() {
  EventRegistrationToken token;

  // ページの移動：このアプリの画面（127.0.0.1 の決まったパス）以外へは移動させない
  {
    auto* cb = new Callback<ICoreWebView2NavigationStartingEventHandler, ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs*>(
        IID_ICoreWebView2NavigationStartingEventHandler, [this](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
          LPWSTR raw = nullptr;
          args->get_Uri(&raw);
          std::wstring uri = TakeCoString(raw);
          if (!IsAppUrl(uri)) {
            args->put_Cancel(TRUE);
            RequestExternal(uri);
          }
          return S_OK;
        });
    webview_->add_NavigationStarting(cb, &token);
    cb->Release();
  }
  {
    auto* cb = new Callback<ICoreWebView2NavigationStartingEventHandler, ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs*>(
        IID_ICoreWebView2NavigationStartingEventHandler, [this](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
          LPWSTR raw = nullptr;
          args->get_Uri(&raw);
          if (!IsAppUrl(TakeCoString(raw))) args->put_Cancel(TRUE);
          return S_OK;
        });
    webview_->add_FrameNavigationStarting(cb, &token);
    cb->Release();
  }
  // 新しいウィンドウ（target="_blank" のリンクなど）：アプリ内では開かず、許可された https だけ既定のブラウザへ
  {
    auto* cb = new Callback<ICoreWebView2NewWindowRequestedEventHandler, ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs*>(
        IID_ICoreWebView2NewWindowRequestedEventHandler, [this](ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs* args) -> HRESULT {
          args->put_Handled(TRUE);
          LPWSTR raw = nullptr;
          args->get_Uri(&raw);
          RequestExternal(TakeCoString(raw));
          return S_OK;
        });
    webview_->add_NewWindowRequested(cb, &token);
    cb->Release();
  }
  // カメラ・位置情報・通知などの許可要求は、すべて断る
  {
    auto* cb = new Callback<ICoreWebView2PermissionRequestedEventHandler, ICoreWebView2*, ICoreWebView2PermissionRequestedEventArgs*>(
        IID_ICoreWebView2PermissionRequestedEventHandler, [](ICoreWebView2*, ICoreWebView2PermissionRequestedEventArgs* args) -> HRESULT {
          args->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
          return S_OK;
        });
    webview_->add_PermissionRequested(cb, &token);
    cb->Release();
  }
  // 画面の表示が止まったときは読み込み直す。WebView2 そのものが終了したときは、ウィンドウを閉じる
  {
    auto* cb = new Callback<ICoreWebView2ProcessFailedEventHandler, ICoreWebView2*, ICoreWebView2ProcessFailedEventArgs*>(
        IID_ICoreWebView2ProcessFailedEventHandler, [this](ICoreWebView2*, ICoreWebView2ProcessFailedEventArgs* args) -> HRESULT {
          COREWEBVIEW2_PROCESS_FAILED_KIND kind;
          if (FAILED(args->get_ProcessFailedKind(&kind))) return S_OK;
          if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED) {
            Fail(E_FAIL, L"画面の表示");
          } else if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED || kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE) {
            if (webview_) webview_->Reload();
          }
          return S_OK;
        });
    webview_->add_ProcessFailed(cb, &token);
    cb->Release();
  }

  // レポートの「HTMLとして保存」：保存先をこのウィンドウの「名前を付けて保存」画面で選んでもらう
  ICoreWebView2_4* w4 = nullptr;
  if (SUCCEEDED(webview_->QueryInterface(IID_ICoreWebView2_4, (void**)&w4)) && w4) {
    auto* cb = new Callback<ICoreWebView2DownloadStartingEventHandler, ICoreWebView2*, ICoreWebView2DownloadStartingEventArgs*>(
        IID_ICoreWebView2DownloadStartingEventHandler, [this](ICoreWebView2*, ICoreWebView2DownloadStartingEventArgs* args) -> HRESULT {
          ICoreWebView2DownloadOperation* op = nullptr;
          LPWSTR raw = nullptr;
          if (SUCCEEDED(args->get_DownloadOperation(&op)) && op) op->get_Uri(&raw);
          SafeRelease(op);
          if (!IsAppUrl(TakeCoString(raw))) {
            args->put_Cancel(TRUE);
            return S_OK;
          }
          args->put_Handled(TRUE);  // ブラウザのダウンロード一覧は出さない
          ICoreWebView2Deferral* deferral = nullptr;
          if (FAILED(args->GetDeferral(&deferral)) || !deferral) {
            args->put_Cancel(TRUE);
            return S_OK;
          }
          args->AddRef();
          PostMessageW(hwnd_, WM_APP_DOWNLOAD, 0, (LPARAM) new PendingDownload{args, deferral});
          return S_OK;
        });
    w4->add_DownloadStarting(cb, &token);
    cb->Release();
  }
  SafeRelease(w4);

  // 右クリックメニュー：コピー・貼り付けなどの編集操作だけを残す（戻る・印刷・検証などは出さない）
  ICoreWebView2_11* w11 = nullptr;
  if (SUCCEEDED(webview_->QueryInterface(IID_ICoreWebView2_11, (void**)&w11)) && w11) {
    auto* cb = new Callback<ICoreWebView2ContextMenuRequestedEventHandler, ICoreWebView2*, ICoreWebView2ContextMenuRequestedEventArgs*>(
        IID_ICoreWebView2ContextMenuRequestedEventHandler, [](ICoreWebView2*, ICoreWebView2ContextMenuRequestedEventArgs* args) -> HRESULT {
          static const std::set<std::wstring> keep = {L"cut", L"copy", L"paste", L"pasteAndMatchStyle", L"selectAll", L"undo", L"redo"};
          ICoreWebView2ContextMenuItemCollection* items = nullptr;
          if (FAILED(args->get_MenuItems(&items)) || !items) {
            args->put_Handled(TRUE);
            return S_OK;
          }
          UINT32 count = 0;
          items->get_Count(&count);
          for (UINT32 i = count; i-- > 0;) {
            ICoreWebView2ContextMenuItem* item = nullptr;
            bool remove = true;
            if (SUCCEEDED(items->GetValueAtIndex(i, &item)) && item) {
              LPWSTR name = nullptr;
              item->get_Name(&name);
              COREWEBVIEW2_CONTEXT_MENU_ITEM_KIND kind;
              bool isCommand = SUCCEEDED(item->get_Kind(&kind)) && kind == COREWEBVIEW2_CONTEXT_MENU_ITEM_KIND_COMMAND;
              remove = !(isCommand && keep.count(TakeCoString(name)) > 0);
              item->Release();
            }
            if (remove) items->RemoveValueAtIndex(i);
          }
          items->get_Count(&count);
          if (count == 0) args->put_Handled(TRUE);  // 残るものがなければメニューを出さない
          items->Release();
          return S_OK;
        });
    w11->add_ContextMenuRequested(cb, &token);
    cb->Release();
  }
  SafeRelease(w11);
}

void App::PickFolder() {
  if (picking_) return;  // Node.js 側でも二重には頼まない
#ifdef KC_SMOKE_TEST
  // 動作確認用のビルドだけ：KC_SMOKE_PICK があれば、画面を出さずにそのフォルダを選んだことにする
  wchar_t fixed[MAX_PATH];
  if (GetEnvironmentVariableW(L"KC_SMOKE_PICK", fixed, MAX_PATH)) return Send("PICKED " + ToUtf8(fixed));
#endif
  picking_ = true;
  BringToFront();  // フォルダ選択の画面は、このウィンドウを親にして手前に出す
  std::string result = "PICK-FAILED";
  IFileOpenDialog* dialog = nullptr;
  if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_IFileOpenDialog, (void**)&dialog)) && dialog) {
    FILEOPENDIALOGOPTIONS opts = 0;
    dialog->GetOptions(&opts);
    dialog->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR);
    dialog->SetTitle(L"チェックするアプリのフォルダを選んでください");
    dialog->SetOkButtonLabel(L"このフォルダを選ぶ");
    openDialog_ = dialog;
    HRESULT hr = dialog->Show(hwnd_);  // hwnd_ が親（モーダル）。親が前面にあるので、この画面も前面に出る
    openDialog_ = nullptr;
    if (SUCCEEDED(hr)) {
      IShellItem* item = nullptr;
      PWSTR path = nullptr;
      if (SUCCEEDED(dialog->GetResult(&item)) && item && SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
        result = "PICKED " + ToUtf8(path);
      }
      if (path) CoTaskMemFree(path);
      SafeRelease(item);
    } else if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
      result = "PICK-CANCELLED";
    }
    dialog->Release();
  }
  picking_ = false;
  Send(result);
  if (closing_) DestroyWindow(hwnd_);
}

void App::ShowDownloadDialog(PendingDownload* pending) {
  ICoreWebView2DownloadStartingEventArgs* args = pending->args;
  LPWSTR raw = nullptr;
  args->get_ResultFilePath(&raw);
  std::wstring suggested = TakeCoString(raw);
  size_t slash = suggested.find_last_of(L"\\/");
  std::wstring name = slash == std::wstring::npos ? suggested : suggested.substr(slash + 1);
  bool saved = false;
  IFileSaveDialog* dialog = nullptr;
  if (!closing_ && SUCCEEDED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_IFileSaveDialog, (void**)&dialog)) && dialog) {
    COMDLG_FILTERSPEC filter[] = {{L"HTML ファイル", L"*.html"}};
    dialog->SetFileTypes(1, filter);
    dialog->SetDefaultExtension(L"html");
    if (!name.empty()) dialog->SetFileName(name.c_str());
    dialog->SetTitle(L"レポートを保存");
    FILEOPENDIALOGOPTIONS opts = 0;
    dialog->GetOptions(&opts);
    dialog->SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT | FOS_NOCHANGEDIR);
    if (SUCCEEDED(dialog->Show(hwnd_))) {
      IShellItem* item = nullptr;
      PWSTR path = nullptr;
      if (SUCCEEDED(dialog->GetResult(&item)) && item && SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
        saved = SUCCEEDED(args->put_ResultFilePath(path));
      }
      if (path) CoTaskMemFree(path);
      SafeRelease(item);
    }
    dialog->Release();
  }
  if (!saved) args->put_Cancel(TRUE);
  pending->deferral->Complete();
  pending->deferral->Release();
  args->Release();
  delete pending;
}

void App::OnLine(const std::string& line) {
  if (line == "PICK") return PickFolder();
  if (line == "QUIT") {
    closing_ = true;
    if (openDialog_) openDialog_->Close(HRESULT_FROM_WIN32(ERROR_CANCELLED));  // 選択中ならその画面を閉じてから終わる
    else DestroyWindow(hwnd_);
    return;
  }
  const std::string ext = "OPEN-EXTERNAL ";
  if (line.compare(0, ext.size(), ext) == 0) {
    std::wstring uri = FromUtf8(line.substr(ext.size()));
    // Node.js 側でも確認済み。ここでも https であること・空白や引用符を含まないことを確かめる
    bool ok = StartsWith(uri, L"https://") && uri.size() <= 2048;
    for (wchar_t c : uri) {
      if (c <= 0x20 || c == L'"' || c == 0x7f) ok = false;
    }
    if (ok) ShellExecuteW(hwnd_, L"open", uri.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
  }
}

void App::Resize() {
  if (!controller_) return;
  RECT rc;
  GetClientRect(hwnd_, &rc);
  controller_->put_Bounds(rc);
}

void App::Fail(HRESULT hr, const wchar_t* what) {
  if (closing_) return;
  closing_ = true;
  char code[16];
  wsprintfA(code, "%08lX", (unsigned long)hr);
  Send(std::string("FAILED ") + code);
  wchar_t msg[512];
  wsprintfW(msg, L"%s で問題が起きたため、公開前チェックを終了します。\n\nもう一度起動しても直らない場合は、次のコードを添えて報告してください。\nコード: 0x%08lX", what, (unsigned long)hr);
  MessageBoxW(hwnd_, msg, kTitle, MB_OK | MB_ICONERROR);
  DestroyWindow(hwnd_);
}

void App::NoRuntime() {
  if (closing_) return;
  closing_ = true;
  Send("NO-RUNTIME");
  int r = MessageBoxW(hwnd_,
                      L"画面の表示に使う「Microsoft Edge WebView2 ランタイム」が、このPCに見つかりませんでした。\n\n"
                      L"Windows 11 には最初から入っています。Windows 10 では、Microsoft の公式ページから「Evergreen ブートストラップ」を"
                      L"インストールしてから、もう一度起動してください。\n\nMicrosoft の公式ページを開きますか？",
                      kTitle, MB_YESNO | MB_ICONINFORMATION);
  if (r == IDYES) ShellExecuteW(hwnd_, L"open", kRuntimePage, nullptr, nullptr, SW_SHOWNORMAL);
  DestroyWindow(hwnd_);
}

LRESULT App::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_SIZE:
      Resize();
      return 0;
    case WM_MOVE:
    case WM_MOVING:
      if (controller_) controller_->NotifyParentWindowPositionChanged();
      break;
    case WM_SETFOCUS:
      if (controller_) controller_->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
      return 0;
    case WM_DPICHANGED: {
      const RECT* r = reinterpret_cast<const RECT*>(lp);
      SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
      return 0;
    }
    case WM_GETMINMAXINFO: {
      auto* mm = reinterpret_cast<MINMAXINFO*>(lp);
      UINT dpi = GetDpiForWindow(hwnd);
      mm->ptMinTrackSize.x = MulDiv(480, (int)dpi, 96);
      mm->ptMinTrackSize.y = MulDiv(400, (int)dpi, 96);
      return 0;
    }
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = BeginPaint(hwnd, &ps);
      if (!ready_) {
        RECT rc;
        GetClientRect(hwnd, &rc);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(0x44, 0x44, 0x44));
        DrawTextW(dc, L"起動しています…", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
      }
      EndPaint(hwnd, &ps);
      return 0;
    }
    case WM_APP_LINE: {
      auto* line = reinterpret_cast<std::string*>(lp);
      OnLine(*line);
      delete line;
      return 0;
    }
    case WM_APP_STDIN_CLOSED:
      // Node.js 側が終了した。画面だけが残らないよう閉じる
      closing_ = true;
      if (openDialog_) openDialog_->Close(HRESULT_FROM_WIN32(ERROR_CANCELLED));
      else DestroyWindow(hwnd);
      return 0;
    case WM_APP_DOWNLOAD:
      ShowDownloadDialog(reinterpret_cast<PendingDownload*>(lp));
      return 0;
    case WM_CLOSE:
      if (picking_) return 0;  // フォルダ選択中は、先にその画面を閉じてもらう
      closing_ = true;
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY:
      if (controller_) controller_->Close();
      SafeRelease(webview_);
      SafeRelease(controller_);
      SafeRelease(env_);
      Send("CLOSED");
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

int ShowFatal() {
  // 標準入力で受け取った文章を、エラーとして表示する（Node.js 側の予期しないエラー用）
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  std::string all, line;
  while (all.size() < kMaxLine && ReadLineBlocking(in, line)) all += line + "\n";
  all += line;
  std::wstring msg = FromUtf8(all);
  if (msg.empty()) msg = L"予期しないエラーが発生しました。";
  MessageBoxW(nullptr, msg.c_str(), kTitle, MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
  return 0;
}

bool IsValidAppUrl(const std::wstring& url) {
  // http://127.0.0.1:<port>/r/<16進数>/ の形だけを受け付ける
  const std::wstring head = L"http://127.0.0.1:";
  if (!StartsWith(url, head) || url.size() > 200) return false;
  size_t i = head.size(), digits = 0;
  while (i < url.size() && iswdigit(url[i])) i++, digits++;
  if (digits == 0 || digits > 5 || url.compare(i, 3, L"/r/") != 0) return false;
  i += 3;
  size_t hex = 0;
  while (i < url.size() && iswxdigit(url[i]) && !iswupper(url[i])) i++, hex++;
  return hex >= 32 && i == url.size() - 1 && url[i] == L'/';
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int) {
  // DLL は System32 と、明示したパスからだけ読み込む（同じフォルダに置かれた偽の DLL を読まない）
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  bool fatal = argv && argc >= 2 && lstrcmpW(argv[1], L"--fatal") == 0;
  if (argv) LocalFree(argv);
  if (fatal) return ShowFatal();

  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  g_out = GetStdHandle(STD_OUTPUT_HANDLE);
  if (in == nullptr || in == INVALID_HANDLE_VALUE || GetFileType(in) != FILE_TYPE_PIPE) {
    MessageBoxW(nullptr, L"このファイルは、公開前チェック（koukai-check.exe）から自動で使われる部品です。\n公開前チェックを使うときは、ダウンロードした koukai-check の exe をダブルクリックしてください。", kTitle,
                MB_OK | MB_ICONINFORMATION);
    return 2;
  }

  std::string first;
  if (!ReadLineBlocking(in, first) || first.compare(0, 9, "NAVIGATE ") != 0) return 2;
  std::wstring url = FromUtf8(first.substr(9));
  if (!IsValidAppUrl(url)) {
    Send("FAILED BAD-URL");
    return 2;
  }

  if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 3;
  if (!g_app.Init(inst, url)) {
    Send("FAILED WINDOW");
    return 3;
  }

  // Node.js からの指示を読むスレッド。1行ごとに画面のスレッドへ渡す
  HWND target = g_app.hwnd();
  std::thread([in, target]() {
    std::string line;
    while (ReadLineBlocking(in, line)) PostMessageW(target, WM_APP_LINE, 0, (LPARAM) new std::string(line));
    PostMessageW(target, WM_APP_STDIN_CLOSED, 0, 0);
  }).detach();

  MSG m;
  while (GetMessageW(&m, nullptr, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  CoUninitialize();
  ExitProcess(0);  // 読み取り用のスレッドが止まっていても終了する
}
