#include <stddef.h>

extern int verify_file(const char* xml_file, const char* key, size_t key_len);
extern int verify_file_pem(const char* xml_file, const char* key_file);
extern int verify_doc(const char* xml, size_t xml_len, const char* key, size_t key_len);
extern int verify_doc_pem(const char* xml, size_t xml_len, const char* key_file);

