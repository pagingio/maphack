#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>

#define LEFT    0x01
#define PLUS    0x02
#define SPACE   0x04
#define SPECIAL 0x08
#define ZERO    0x10
#define SIGN    0x20 /* signed if set */
#define SMALL   0x40 /* 'abcdef' if set, 'ABCDEF' otherwise */

#define isdigit(c) ((c) >= '0' && (c) <= '9')

void* m_malloc(size_t length)
{
  LPVOID newBuffer;
  newBuffer = VirtualAlloc( NULL, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
  return newBuffer;
}

void m_free(void* buffer, size_t length)
{
  VirtualFree(buffer, length, MEM_DECOMMIT);
}

int m_wcscmp(wchar_t* source, wchar_t* dest)
{
  wchar_t*  p1;
  wchar_t*  p2;

  p1 = source;
  p2 = dest;
  while (*p1 != 0)
  {
    if (*p1 > *p2)
      return 1;
    else if (*p1 < *p2)
      return -1;

    p1++;
    p2++;
  }
  return 0;
}

DWORD GetProcessID(LPCTSTR pName)
{
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) {
    return 0;
  }
  PROCESSENTRY32 pe = { sizeof(pe) };
  BOOL fOk;
  for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe)) {
    if (!m_wcscmp(pe.szExeFile, (wchar_t*)pName)) {
      CloseHandle(hSnapshot);
      return pe.th32ProcessID;
    }
  }
  return 0;
}

ULONG SafeWrite(PULONG address, ULONG newValue)
{
  DWORD   oldFlags, newFlags;
  ULONG   oldValue;
  newFlags = PAGE_READWRITE;
  VirtualProtect(address, sizeof(ULONG), newFlags, &oldFlags);
  oldValue = InterlockedExchange((LONG*)address, newValue);
  VirtualProtect(address, sizeof(ULONG), oldFlags, &newFlags);
  return oldValue;
}

static char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
static char *upper_digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

size_t m_strnlen(const char *s, size_t count)
{
  const char *sc;
  for (sc = s; *sc != '\0' && count--; ++sc);
  return sc - s;
}

size_t m_strlen(const char *s)
{
  const char *sc;
  for (sc = s; *sc != '\0'; ++sc);
  return sc - s;
}

int get_wide (const char **s);
void number_to_string (long num, int base, int flags, int wide, int precision, char **s);

int vsprintf (char *str, const char *format, va_list ap) {
  char c;
  char *start = str;
  int flags;
  int wide;
  int precision;
  int qualifier;
  char *s;
  int i, len, base;

  while ((c = *format++) != 0) {
    if (c != '%') { *str++ = c; continue; }
    if (*format == '%') { *str++ = '%'; format++; continue; }

    /* get flags */
    flags = 0;
    while (1) {
      if (*format == '-') { flags |= LEFT;    format++; continue; }
      if (*format == '+') { flags |= PLUS;    format++; continue; }
      if (*format == ' ') { flags |= SPACE;   format++; continue; }
      if (*format == '#') { flags |= SPECIAL; format++; continue; }
      if (*format == '0') { flags |= ZERO   ; format++; continue; }
      break;
    }

    /* get wide */
    wide = -1;
    if (isdigit (*format)) wide = get_wide ((const char **)(&format));
    else if (*format == '*') { wide = va_arg (ap, int); format++; }

    /* get precision */
    precision = -1;
    if (*format == '.') {
      format++;
      if (isdigit (*format))
        precision = get_wide ((const char **)(&format));
      else if (*format == '*') {
        precision = va_arg (ap, int);
        format++;
      }
      else precision = 0;
    }

    /* get qualifier */
    qualifier = -1;
    if ((*format == 'h') || (*format == 'l')) qualifier = *format++;

    /* get format */
    switch (*format++) {
            case 'i':
            case 'd':
              flags |= SIGN;
              if (precision != -1) flags &= ~ZERO;
              switch (qualifier) {
            case 'h':
              number_to_string ((short) va_arg (ap, int), 10, flags,
                wide, precision, &str);
              break;
            case 'l':
              number_to_string (va_arg (ap, long), 10, flags,
                wide, precision, &str);
              break;
            default:
              number_to_string (va_arg (ap, int), 10, flags,
                wide, precision, &str);
              break;
              }
              break;

            case 'u':
              base = 10;
              goto num_to_str_without_sign;

            case 'o':
              base = 8;
              goto num_to_str_without_sign;

            case 'x':
              flags |= SMALL;
            case 'X':
              base = 16;

num_to_str_without_sign:
              flags &= (~PLUS & ~SPACE);
              if (precision != -1) flags &= ~ZERO;
              switch (qualifier) {
            case 'h':
              number_to_string ((unsigned short) va_arg (ap, int), \
                base, flags, wide, precision, &str);
              break;
            case 'l':
              number_to_string ((unsigned long) va_arg (ap, long), \
                base, flags, wide, precision, &str);
              break;
            default:
              number_to_string((unsigned int)va_arg (ap, int), \
                base, flags, wide, precision, &str);
              break;
              }
              break;

            case 's':
              s = va_arg (ap, char *);
              len = m_strlen (s);
              if ((precision >= 0) && (len > precision)) len = precision;

              /* rigth justified : pad with spaces */
              if (!(flags & LEFT)) while (len < wide--) *str++ = ' ';
              for (i = 0; i < len; i++) *str++ = *s++;
              /* left justified : pad with spaces */
              while (len < wide--) *str++ = ' ';
              break;

            case 'c':
              /* rigth justified : pad with spaces */
              if (!(flags & LEFT)) while (1 < wide--) *str++ = ' ';
              *str++ = (unsigned char) va_arg (ap, int);
              /* left justified : pad with spaces */
              while (1 < wide--) *str++ = ' ';
              break;

            default:
              return -1;
    }
  }
  *str = 0;

  return (int)(str-start);
}

int get_wide (const char **s) {
  int res = 0;
  while (isdigit (**s)) res = 10*res + *((*s)++) - '0';
  return res;
}

#define LONG_STRSIZE_BASE_2 32

void number_to_string (long num, int base, int flags, int wide, int precision, char **s) {
  char sign;  /* sign printed : '+', '-', ' ', or 0 (no sign) */
  int num_cpy = num;
  unsigned long ul_num = (unsigned long) num; /* for unsigned format */

  /* string representation of num (reversed) */
  char tmp[LONG_STRSIZE_BASE_2];
  int i = 0; /* number of figures in tmp */

  const char *digits = "0123456789ABCDEF";
  if (flags & SMALL) digits = "0123456789abcdef";

  if ((base < 2) || (base > 16)) return;

  if ((flags & SIGN) && (num < 0)) { sign = '-'; num = -num; }
  else sign = (flags & PLUS) ? '+' : ((flags & SPACE) ? ' ' : 0);
  if (sign) wide--;

  if (flags & SPECIAL) {
    if ((base == 16) && (num != 0)) wide -= 2;  /* '0x' or '0X' */
    if (base == 8) { wide--; precision--; }     /* '0' */
  }

  if (num == 0) tmp[i++] = '0';
  /* signed format */
  if (flags & SIGN) {
    while (num != 0) {
      tmp[i++] = digits[num % base];
      num = num / base;
    } 
  }
  /* unsigned format */
  else {
    while (ul_num != 0) {
      tmp[i++] = digits[ul_num % base];
      ul_num = ul_num / base;
    } 
  }

  if (i > precision) precision = i;
  wide -= precision;

  /* wide = number of padding chars */
  /* precision = number of figures after the sign and the special chars */

  /* right justified and no zeropad : pad with spaces */
  if (!(flags & (LEFT + ZERO))) while (wide-- > 0) *((*s)++) = ' ';

  if (sign) *((*s)++) = sign;
  if ((flags & SPECIAL) && (num_cpy != 0)) {
    if (base == 8) *((*s)++) = '0';
    if (base == 16) {
      *((*s)++) = '0';
      if (flags & SMALL) *((*s)++) = 'x';
      else *((*s)++) = 'X';
    }
  }

  /* rigth justified and zeropad : pad with 0 */
  if (!(flags & LEFT)) while (wide-- > 0) *((*s)++) = '0';

  /* print num */
  while (i < precision--) *((*s)++) = '0';
  while (i-- > 0) *((*s)++) = tmp[i];

  /* left justfied : pad with spaces */
  while (wide-- > 0) *((*s)++) = ' ';
}

int sprintf(char *buf, const char *fmt, ...)
{
  va_list args;
  int n;

  va_start(args, fmt);
  n = vsprintf(buf, fmt, args);
  va_end(args);

  return n;
}

void m_memcpy(void* dest, void* source, size_t count)
{

  __asm
  {
    pushad
    mov   esi, source
    mov   edi, dest
    mov   ecx, count
    cld
    rep movsb
    popad
  }
  //unsigned char *p1, *p2;
  //size_t  i;
  //p1 = (unsigned char *)source;
  //p2 = (unsigned char *)dest;
  //for (i = 0; i < length; i++)
  //{
  //  *p2 = *p1;
  //  p1++;
  //  p2++;
  //}
}

void m_memset(void* dest, int value, size_t count)
{
  __asm
  {
    pushad
    mov   eax, value
    mov   edi, dest
    mov   ecx, count
    cld
    rep stosb
    popad
  }
}

void DebugString(char* fmt,...)
{
#define MAX_BUFFER    2048
  char    maxBuffer[MAX_BUFFER];
  va_list ap;
  va_start(ap, fmt);
  vsprintf(maxBuffer, fmt, ap);
  va_end(ap);
  ::OutputDebugStringA(maxBuffer);
}