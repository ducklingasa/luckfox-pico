#define _XOPEN_SOURCE 700

#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

int main(void)
{
	const char text[] = "\303\251\342\202\254\344\270\255";
	const wchar_t expected[] = { 0x00e9, 0x20ac, 0x4e2d, 0 };
	wchar_t decoded[4];
	char encoded[sizeof(text)];
	const char *locale = setlocale(LC_ALL, "");

	if (locale == NULL) {
		fputs("Configured locale is unavailable\n", stderr);
		return EXIT_FAILURE;
	}
	if (strcmp(nl_langinfo(CODESET), "UTF-8") != 0 || MB_CUR_MAX < 3) {
		fprintf(stderr, "Expected UTF-8, got %s (MB_CUR_MAX=%zu)\n",
			nl_langinfo(CODESET), (size_t)MB_CUR_MAX);
		return EXIT_FAILURE;
	}
	if (mbstowcs(decoded, text, 4) != 3 ||
	    wmemcmp(decoded, expected, 4) != 0 ||
	    wcstombs(encoded, decoded, sizeof(encoded)) != sizeof(text) - 1 ||
	    memcmp(encoded, text, sizeof(text)) != 0) {
		fputs("UTF-8 multibyte round-trip failed\n", stderr);
		return EXIT_FAILURE;
	}
	if (!iswprint(0x20ac) || towupper(0x00e9) != 0x00c9) {
		fputs("Unicode classification or case conversion failed\n", stderr);
		return EXIT_FAILURE;
	}
	printf("PASS: %s, %s, UTF-8 round-trip and wide characters\n",
	       locale, nl_langinfo(CODESET));
	return EXIT_SUCCESS;
}
