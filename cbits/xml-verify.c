#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "xml-verify.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

int init() {
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    if(xmlSecInit() < 0) {
        return(-2);
    }

    if(xmlSecCheckVersion() != 1) {
        return(-3);
    }

#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        return(-4);     
    }
#endif

    if(xmlSecCryptoAppInit(NULL) < 0) {
        return(-5);
    }

    if(xmlSecCryptoInit() < 0) {
        return(-6);
    }
    return 0;
}

void deinit() {
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
}

// If either len is 0, we assume a file path.
int verify(const char *xml, size_t xml_len, const char *key, size_t key_len) {
    init();
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;
    
    if (xml_len == 0) {
      doc = xmlParseFile(xml);
    } else {
      doc = xmlParseMemory(xml, xml_len);
    }
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        res = -7;
        goto done;      
    }
    
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        res = -8;
        goto done;      
    }

    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        res = -9;
        goto done;
    }

    if (key_len == 0) {
      dsigCtx->signKey = xmlSecCryptoAppKeyLoad(key, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    } else {
      dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory((const xmlSecByte *)key, (xmlSecSize)key_len, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    }
    if(dsigCtx->signKey == NULL) {
        res = -10;
        goto done;
    }

    if(xmlSecKeySetName(dsigCtx->signKey, "memory pem") < 0) {
        res = -11;
        goto done;
    }

    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        res = -12;
        goto done;
    }
        
    if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
        res = 0;
    } else {
        res = -1;
    }    

done:    
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }
    
    if(doc != NULL) {
        xmlFreeDoc(doc); 
    }
    deinit();
    return(res);
}

int verify_file(const char* xml_file, const char* key, size_t key_len) {
  return verify(xml_file, 0, key, key_len);
}

int verify_file_pem(const char* xml_file, const char* key_file) {
  return verify(xml_file, 0, key_file, 0);
}

int verify_doc(const char* xml, size_t xml_len , const char* key, size_t key_len) {
  return verify(xml, xml_len, key, key_len);
}

int verify_doc_pem(const char* xml, size_t xml_len, const char* key_file) {
  return verify(xml, xml_len, key_file, 0);
}
