package me.sniggle.pgp.crypt;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

/**
 * Created by iulius on 19/09/15.
 */
@RunWith(Parameterized.class)
public class PGPMessageEncryptorDecryptTest {

  private MessageEncryptor messageEncryptor;
  private String password;
  private String privateKeyFilename;
  private String encryptedDataFilename;
  private String expectedMessage;
  private String mesg;
  private static final Logger LOGGER = LoggerFactory.getLogger(PGPMessageEncryptorDecryptTest.class);
  public PGPMessageEncryptorDecryptTest(String password, String privateKeyFilename, String encryptedDataFilename, String expectedMessage) {
    this.password = password;
    this.privateKeyFilename = privateKeyFilename;
    this.encryptedDataFilename = encryptedDataFilename;
    this.expectedMessage = expectedMessage;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList( new Object[][] {
       // { "06Pgp2009@", "private-key.asc", "test-message.txt.gpg", "Hello World!" }
        { "testpassword", "testcase-4-sec.asc", "test-message.txt.gpg", "Hello World!" }
    });
  }

  @Before
  public void setup() {
    messageEncryptor = PGPWrapperFactory.getEncyptor();
  }

  @Test
  public void testDecryptWithoutSignage() throws FileNotFoundException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    //boolean actualResult = messageEncryptor.decrypt(password, getClass().getResourceAsStream(privateKeyFilename), getClass().getResourceAsStream(encryptedDataFilename), baos);
  //  assertEquals(expectedMessage != null, actualResult);
    try {

     //  mesg = readFile("test-message.txt", StandardCharsets.UTF_8);
      mesg = readFile("test-message.txt", StandardCharsets.UTF_8);
     // System.out.println(mesg);

      JSONObject jo= new JSONObject(mesg);
     // JSONObject jo= new JSONObject(new String(baos.toByteArray()));
      String base64encodedpayload = (jo.getString("vehicleData"));
      String encryptedpayload = new String(Base64.getDecoder().decode(base64encodedpayload));
      //  String plaintextpayload =
      InputStream inStream = new ByteArrayInputStream(encryptedpayload.getBytes());
      boolean actualResult = messageEncryptor.decrypt(password, getClass().getResourceAsStream(privateKeyFilename), inStream, baos);
      assertEquals(expectedMessage != null, actualResult);
      String decryptedPayload = new String(baos.toByteArray());
      System.out.println(decryptedPayload);
    }
    catch (IOException ioe)
    {
      ioe.printStackTrace();
    }
    catch ( JSONException je)
    {
      LOGGER.error("{}", je.getMessage());
    }
    //assertEquals(mesg, new String(baos.toByteArray()));
  }

  @After
  public void cleanUp() {
    messageEncryptor = null;
  }
  static String readFile(String path, Charset encoding)
          throws IOException
  {
    System.out.println(Paths.get(path).toAbsolutePath());
    byte[] encoded = Files.readAllBytes(Paths.get(path));
    return new String(encoded, encoding);
  }
}
