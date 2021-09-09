{-# LANGUAGE ForeignFunctionInterface, ViewPatterns #-}

{-|
Description: Library for Verifying XML Signatures
-}


module Crypto.PubKey.Xml
( -- * Verifying
  verifyXml
, verifyXmlFile
, verifyXmlPem
, verifyXmlFilePem
) where

import Text.XML.HXT.Core
import Control.Monad.Trans
import Data.X509
import Data.PEM
import Data.Maybe
import qualified Data.ByteString as BS
import Crypto.Store.X509
import Foreign.C.Types
import Foreign.C.String
import Crypto.PubKey.Xml.Errors

foreign import ccall "verify_file" cVerifyFile :: CString -> CString -> CSize -> IO CInt
foreign import ccall "verify_file_pem" cVerifyFilePem :: CString -> CString -> IO CInt
foreign import ccall "verify_doc" cVerifyDoc :: CString -> CSize -> CString -> CSize -> IO CInt
foreign import ccall "verify_doc_pem" cVerifyDocPem :: CString -> CSize -> CString -> IO CInt

returnCode :: CInt -> Either XmlVerifyError Bool
returnCode ( 0 ) = Right True
returnCode (-1 ) = Right False
returnCode (-2 ) = Left XmlSecInitFailed
returnCode (-3 ) = Left XmlSecIncomp     
returnCode (-4 ) = Left XmlSecCryptoFail
returnCode (-5 ) = Left CryptoInitFailed
returnCode (-6 ) = Left XmlCryptoFailed 
returnCode (-7 ) = Left XmlParseFail    
returnCode (-8 ) = Left XmlNoStartNode  
returnCode (-9 ) = Left XmlSigCreateFail
returnCode (-10) = Left XmlPemLoadFail  
returnCode (-11) = Left XmlPemNameFail  
returnCode (-12) = Left VeryifyFail
returnCode  _    = Right False

-- | verify XML file with given public key
verifyXmlFile :: (MonadIO m) => FilePath -> PubKey -> m (Either XmlVerifyError Bool)
verifyXmlFile xml key = do
  let pem = writePubKeyFileToMemory [key]
  ret <- liftIO $ withCString xml $
    \cXml -> BS.useAsCStringLen pem $
    \(cPem, fromIntegral -> len) -> fromIntegral <$> cVerifyFile cXml cPem len
  return $ returnCode ret

-- | verify XML document with given public key
verifyXml :: (MonadIO m) => XmlTree -> PubKey -> m (Either XmlVerifyError Bool)
verifyXml xml key = do
  let pem = writePubKeyFileToMemory [key]
  let xml' = listToMaybe $ runLA (writeDocumentToString []) xml
  case xml' of
    Nothing  -> return $ Left XmlParseFail
    Just xml -> do
      ret <- liftIO $ withCStringLen xml $
        \(cXml, fromIntegral -> xLen) -> BS.useAsCStringLen pem $
        \(cPem, fromIntegral -> pLen) -> fromIntegral <$> cVerifyDoc cXml xLen cPem pLen
      return $ returnCode ret

-- | verify XML file against a public key in a pem file
verifyXmlFilePem :: (MonadIO m) => FilePath -- ^ XML document path
                                -> FilePath -- ^ PEM file path
                                -> m (Either XmlVerifyError Bool)
verifyXmlFilePem xml pem = do
  ret <- liftIO $ withCString xml $
    \cXml -> withCString pem $ 
    \cPem -> fromIntegral <$> cVerifyFilePem cXml cPem
  return $ returnCode ret

-- | Verify XML against a public key provided in a pem file
verifyXmlPem :: (MonadIO m) => XmlTree -> FilePath -> m (Either XmlVerifyError Bool)
verifyXmlPem xml pem = do
  let xml' = listToMaybe $ runLA (writeDocumentToString []) xml
  case xml' of
    Nothing  -> return $ Left XmlParseFail
    Just xml -> do
      ret <- liftIO $ withCStringLen xml $
        \(cXml, fromIntegral -> xLen) -> withCString pem $
        \cPem                         -> fromIntegral <$> cVerifyDocPem cXml xLen cPem
      return $ returnCode ret
