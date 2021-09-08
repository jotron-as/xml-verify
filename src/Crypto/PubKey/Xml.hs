
{-|
Description: Library for Verifying and Signing XML
-}


module Crypto.PubKey.Xml
( -- * Verifying
  verifyXml
, verifyXmlFile
, verifyXmlPem
, verifyXmlFilePem
  -- * Signing
, signXml
, signXmlPem
) where

import Text.XML.HXT.Core
import Control.Monad.Trans
import Data.X509

-- | verify XML file with given public key
verifyXmlFile :: (MonadIO m) => FilePath -> PubKey -> m Bool
verifyXmlFile = undefined

-- | verify XML document with given public key
verifyXml :: XmlTree -> PubKey -> Bool
verifyXml = undefined

-- | verify XML file against a public key in a pem file
verifyXmlFilePem :: (MonadIO m) => FilePath -- ^ XML document path
                                -> FilePath -- ^ PEM file path
                                -> m Bool
verifyXmlFilePem = undefined

-- | Verify XML against a public key provided in a pem file
verifyXmlPem :: (MonadIO m) => XmlTree -> FilePath -> m Bool
verifyXmlPem = undefined

-- | Sign some XML with a given private key
signXml :: XmlTree -> PrivKey -> XmlTree
signXml = undefined

-- | Sign some XML with a private key given in a PEM file
signXmlPem :: (MonadIO m) => XmlTree -> FilePath -> m XmlTree
signXmlPem = undefined
