// WebView2.h は "EventToken.h" を読み込むが、MinGW-w64 のヘッダー名は小文字（eventtoken.h）のため、その橋渡し。
// include_next：大文字小文字を区別しない Windows でも、このファイル自身ではなく MinGW-w64 のヘッダーを読む
#include_next <eventtoken.h>
