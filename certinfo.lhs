An experiment in certificate handling with Haskell.

ByteStrings are used for more efficient binary data handling (i.e. the
raw certificate file data).

> import Data.ByteString as BS

Certificates are encoded in PEM format, so they'll need to decoded appropriately.

> import Data.PEM as PEM
> import Data.X509 as X509
> import System.IO.Unsafe (unsafePerformIO)

> displayCertificate :: FilePath -> IO ()
> displayCertificate path = do
>     let cert = loadCert path
>     case 

> showCertificateSubject :: X509.Certificate -> IO ()
> showCertificateSubject cert = do
>     putStrLn $ 

> showCert

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

