CertInfo
========

An experiment in certificate handling with Haskell.
---------------------------------------------------

This is the first completed systems program I've written in Haskell,
with a previously-started but uncompleted other program around as
well. I anticipate reviewing this later for a rewrite; as is, the file
smells. It's an important first step, however, in learning the
language. More importantly, it's something of use to me and solves a
systems problem.

The program
-----------

> module Main where

ByteStrings are used for more efficient binary data handling (i.e. the
raw certificate file data).

> import Data.ByteString as BS

Certificates are encoded in PEM format, so they'll need to be decoded
appropriately.

> import Data.PEM as PEM
> import Data.X509 as X509

ASN1String provides functions for retrieving information about an
ASN.1 string.

> import Data.ASN1.Types.String as ASN1String

> import qualified Control.Monad
> import System.Environment as Env
> import System.IO.Unsafe (unsafePerformIO)

`certinfo` reads a list of PEM-encoded certificates from the command
line and prints their subject line.

> main = do
>     args <- Env.getArgs
>     Control.Monad.mapM displayCertificate args

`displayCertificate` displays the subject line for a single
certificate.

> displayCertificate :: FilePath -> IO ()
> displayCertificate path = do
>     let cert = loadCert path
>     Prelude.putStrLn $ path ++ ": " ++ extractSubject cert

Subject information for a certificate may be had by extracting the
relevent distinguished name (DN) elements from the certificate and
building a string from a list of these values.

> extractSubject :: Maybe X509.Certificate -> String

If no certificate was loaded, it's an invalid certificate as far as
the program is concerned.

> extractSubject Nothing     = "Invalid certificate."

Extracting the subject of a certificate is done by loading the
distinguished name elements and joining them into a comma-separated
list.

> extractSubject cert = collapseSubject . filterNothings $ dnStrings

The distinguished name, being of the `Maybe` type, must return a
`Maybe`, requiring a functor mapping.

>     where dn = fmap X509.certSubjectDN cert

Once the distinguished name has been extracted, the strings in the
distinguished name can be pulled out.

>           dnStrings = Prelude.map (buildDNString dn) fieldOrder

Creating a subject line for the certificate involves collapsing a list
of `String`s produced from the elements of the distinguished name into
one string.

> collapseSubject :: [String] -> String
> collapseSubject [] = ""
> collapseSubject (x:y:xs) = x ++ ", " ++ collapseSubject (y:xs)
> collapseSubject (x:xs)   = x ++ collapseSubject xs

A DNprefix is a string that is used to display an element of a
distinguished name. For example, the prefix for the country element is
"C". This might look like `C=US` when applied to a field.

> type DNPrefix = String

A DNField pairs an X.509 DN element with its prefix.

> type DNField = (X509.DnElement, DNPrefix)

`fieldOrder` is used to specify a list of DN elements and their
prefixes in the order they should be displayed.

> fieldOrder :: [DNField]
> fieldOrder = [(X509.DnCommonName, "CN")
>               ,(X509.DnCountry, "C")
>               ,(X509.DnOrganization, "O")
>               ,(X509.DnOrganizationUnit, "OU")]

The `buildDNString` takes a `DNField` and returns it as a `Maybe
String`. If the element exists, it will be returned as `Just
"Prefix=value"`. For example, if the `(X509.DnCountry, "C")` element
is applied to certificate with a US country field, it will be returned
as `Just "C=US"`.

This function is entirely too complex.

> buildDNString :: Maybe X509.DistinguishedName -> DNField -> Maybe String
> buildDNString (Just dn) field = case printableValue of
>                               Nothing    -> Nothing
>                               Just pv -> Just ((snd field) ++ "=" ++ pv)
>     where getPrintable value = case value of
>               X509.ASN1CharacterString {characterEncoding = ASN1String.Printable} -> 
>                   let maybePV = ASN1String.asn1CharacterToString value in
>                   case maybePV of
>                       Nothing -> ""
>                       Just pv -> pv
>               otherwise -> ""
>           printableValue = let pv = X509.getDnElement (fst field) dn in
>                            case pv of
>                                Nothing -> Nothing
>                                Just pv -> ASN1String.asn1CharacterToString pv
> buildDNString Nothing field = Nothing

`filterNothings` probably has a library function that does the same
thing. It takes a list of `Maybes` and removes the `Nothings`.

> filterNothings :: [Maybe a] -> [a]
> filterNothings [] = []
> filterNothings (x:xs) = case x of
>                              Nothing -> filterNothings xs
>                              Just v  -> v : filterNothings xs

`loadCert` attempts to load a certificate from disk and parse it as an
X.509 certificate. The `unsafePerformIO` is because I'm new to
Haskell, and should be examined for removal. If there is an error
loading the certificate, `Nothing` is returned. Otherwise, `Just` the
certificate is returned.

> loadCert :: FilePath -> Maybe X509.Certificate
> loadCert path = loadCertificatePEM $ unsafePerformIO $ BS.readFile path

Typically certificates are stored on disk in PEM format. This function
takes a `ByteString`, such as the data read from disk; and returns the
certificate data. Still **TODO** is verifying the signature.

> loadCertificatePEM :: ByteString -> Maybe X509.Certificate
> loadCertificatePEM certData = case PEM.pemParseBS certData of
>                                    Left  message -> Nothing
>                                    Right derData -> case extractCertificate derData of
>                                                          Nothing   -> Nothing
>                                                          Just cert -> Just cert

The conversion of `ByteString` to PEM returns a list of `PEM.PEM`
structures, which are records containing the type, headers, and
content of all the PEM-encoded structures parsed.

> extractCertificate :: [PEM.PEM] -> Maybe X509.Certificate
> extractCertificate certs
>     | Prelude.length certs > 0 = case extractLeafCert certs of
>                                  Left _ -> Nothing
>                                  Right cert -> Just $ X509.getCertificate cert
>     | otherwise = Nothing

`extractLeafCert` is a utility function that extracts the last
certificate from a list of PEM certificates (typically, a single
certificate) that represents the leaf certificate in a chain. This is
most of the certificate of interest after validation.

> extractLeafCert :: [PEM.PEM] -> Either String X509.SignedCertificate
> extractLeafCert certs = if isACert then X509.decodeSignedCertificate firstPEM else Left "not a certificate"
>     where isACert = (PEM.pemName $ Prelude.head certs) == "CERTIFICATE"
>           firstPEM = PEM.pemContent $ Prelude.head $ Prelude.reverse certs

