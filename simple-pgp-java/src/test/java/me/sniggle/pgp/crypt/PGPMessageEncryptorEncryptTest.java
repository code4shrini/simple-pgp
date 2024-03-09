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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by iulius on 19/09/15.
 */
@RunWith(Parameterized.class)
public class PGPMessageEncryptorEncryptTest {

  private MessageEncryptor messageEncryptor;
  private final String privateKeyFilename;
  private final String publicKeyFilename;
  private final String plainDataFilename;
  private final String userId;
  private String mesg;
  private String res;
  private static final Logger LOGGER = LoggerFactory.getLogger(PGPMessageEncryptorEncryptTest.class);
  public PGPMessageEncryptorEncryptTest(String publicKeyFilename, String privateKeyFilename, String userId, String plainDataFilename) {
    this.publicKeyFilename = publicKeyFilename;
    this.plainDataFilename = plainDataFilename;
    this.privateKeyFilename = privateKeyFilename;
    this.userId = userId;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList( new Object[][] {
//        { "public-key.asc", "private-key.asc", "code4shrini@gmail.com", "test-message.txt" },
      //  { "testcase-2-pub.asc", "testcase-2-sec.asc", "testcase-2@sniggleme.info", "test-message.txt" },
        { "testcase-4-pub.asc", "testcase-4-sec.asc", "pgp-keypair-test4", "vss-a.json" }
    });
  }

  @Before
  public void setUp() throws Exception {
    messageEncryptor = PGPWrapperFactory.getEncyptor();
  }
/*

  @Test
  public void testEncrypt() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    assertTrue(messageEncryptor.encrypt( getClass().getResourceAsStream(publicKeyFilename), "test-message.txt", getClass().getResourceAsStream(plainDataFilename), baos));
    ByteArrayOutputStream plainResult = new ByteArrayOutputStream();
    assertTrue(messageEncryptor.decrypt("testpassword", getClass().getResourceAsStream(privateKeyFilename), new ByteArrayInputStream(baos.toByteArray()), plainResult));

    try(OutputStream outputStream = new FileOutputStream(plainDataFilename+".1.gpg"))
    {
      baos.writeTo(outputStream);
      mesg = readFile("vss-a.json", StandardCharsets.UTF_8);

    }
    catch (IOException ioe)
    {
      LOGGER.error("{}", ioe.getMessage());
    }
    assertEquals(mesg, new String(plainResult.toByteArray()));
  }
*/

  @Test
  public void testEncryptAndSign() throws FileNotFoundException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ByteArrayOutputStream plainResult= new ByteArrayOutputStream();
    try
    {
      mesg = readFile("vss-a.json", StandardCharsets.UTF_8);
     // System.out.println(mesg);
      assertTrue( messageEncryptor.encrypt(
              getClass().getResourceAsStream(publicKeyFilename),
              getClass().getResourceAsStream(privateKeyFilename),
              userId,
              "testpassword",
              "vss-a.json",
              getClass().getResourceAsStream(plainDataFilename),
              baos));
       String encryptedPayload= new String(baos.toByteArray());
     // System.out.println(encryptedPayload);

      String base64encodedpayload = Base64.getEncoder().encodeToString(encryptedPayload.getBytes());
      JSONObject jo= new JSONObject();
      jo.put("vehicleData",base64encodedpayload);
      System.out.println(jo.toString());
    }
    catch (IOException ioe)
    {
      LOGGER.error("{}", ioe.getMessage());
    }
    catch ( JSONException je)
    {
      LOGGER.error("{}", je.getMessage());
    }
    assertTrue(messageEncryptor.decrypt("testpassword", getClass().getResourceAsStream(privateKeyFilename), new ByteArrayInputStream(baos.toByteArray()), plainResult));

    assertEquals(mesg, new String(plainResult.toByteArray()));
  }
  static String readFile(String path, Charset encoding)
          throws IOException
  {
 //   System.out.println(Paths.get(path).toAbsolutePath());
    byte[] encoded = Files.readAllBytes(Paths.get(path));
    return new String(encoded, encoding);
  }
  @After
  public void tearDown() throws Exception {
    messageEncryptor = null;
  }
}
