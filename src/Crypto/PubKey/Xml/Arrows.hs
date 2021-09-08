{-|
Description: Arrow interface for signing and verifying XML documents
-}

module Crypto.PubKey.Xml.Arrows where

import qualified Crypto.PubKey.Xml as X

import Text.XML.HXT.Core
import Data.X509

isSigned :: (ArrowIf a) => PubKey -> a XmlTree XmlTree
isSigned key = isA $ flip X.verifyXml key

isSignedPem :: (ArrowIOIf a) => FilePath -> a XmlTree XmlTree
isSignedPem pem = isIOA $ flip X.verifyXmlPem pem

sign :: (Arrow a) => PrivKey -> a XmlTree XmlTree
sign key = arr $ flip X.signXml key

signPem :: (ArrowIO a) => FilePath -> a XmlTree XmlTree
signPem pem = arrIO $ flip X.signXmlPem pem
