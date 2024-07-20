package app.organicmaps.downloader;

import android.annotation.TargetApi;
import android.content.Context;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import app.organicmaps.util.log.Logger;

@TargetApi(24)
public class Android7RootCertificateWorkaround
{
  private static final String TAG = Android7RootCertificateWorkaround.class.getSimpleName();

  public static SSLSocketFactory getSslSocketFactory(Context context, int[] certificates)
  {
    try
    {
      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);

      // Load PEM certificates from raw resources.
      for (final int rawCertificateId : certificates)
      {
        try (final InputStream caInput = context.getResources().openRawResource(rawCertificateId))
        {
          final CertificateFactory cf = CertificateFactory.getInstance("X.509");
          final Certificate ca = cf.generateCertificate(caInput);
          keyStore.setCertificateEntry("ca" + rawCertificateId, ca);
        }
      }

      final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(keyStore);

      final SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, tmf.getTrustManagers(), null);
      return sslContext.getSocketFactory();
    }
    catch (Exception e)
    {
      e.printStackTrace();
      Logger.e(TAG, "Failed to load certificates: " + e.getMessage());
    }
    return null;
  }
}
