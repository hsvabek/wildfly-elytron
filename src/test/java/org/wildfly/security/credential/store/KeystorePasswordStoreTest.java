/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.credential.store;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.SystemUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;


/**
 * {@code KeyStoreCredentialStore} tests
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>,
 *         <a href="mailto:hsvabek@redhat.com">Hynek Svabek</a>.
 */
public class KeystorePasswordStoreTest extends AbstractCredentialStoreTest {

    private static final Provider provider = new WildFlyElytronProvider();

    private static String BASE_STORE_DIRECTORY = "target/ks-cred-stores";
    private static Map<String, String> stores = new HashMap<>();
    static {
        stores.put("ONE", BASE_STORE_DIRECTORY + "/keystore1.jceks");
        stores.put("TWO", BASE_STORE_DIRECTORY + "/keystore2.jceks");
        stores.put("THREE", BASE_STORE_DIRECTORY + "/keystore3.jceks");
    }

    /**
     * Clean all vaults.
     */
    public static void cleanCredentialStores() {
        File dir = new File(BASE_STORE_DIRECTORY);
        dir.mkdirs();

        for (String f: stores.values()) {
            File file = new File(f);
            file.delete();
        }
    }

    static CredentialStore newCredentialStoreInstance() throws NoSuchAlgorithmException {
        return CredentialStore.getInstance(KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
    }

    /**
     * Convert {@code char[]} password to {@code PasswordCredential}
     * @param password to convert
     * @return new {@code PasswordCredential}
     * @throws UnsupportedCredentialTypeException should never happen as we have only supported types and algorithms
     */
    PasswordCredential createCredentialFromPassword(char[] password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    /**
     * Converts {@code PasswordCredential} to {@code char[]} password
     * @param passwordCredential to convert
     * @return plain text password as {@code char[]}
     */
    char[] getPasswordFromCredential(PasswordCredential passwordCredential) {
        Assert.assertNotNull("passwordCredential parameter", passwordCredential);
        return passwordCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword);
    }

    /**
     * Register security provider containing {@link org.wildfly.security.credential.store.CredentialStoreSpi} implementation.
     */
    @BeforeClass
    public static void setup() throws Exception {
        Security.addProvider(provider);
        cleanCredentialStores();
        // setup vaults that need to be complete before a test starts
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("TWO"))
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("secret_store_TWO")
                .addPassword("alias1", "secret-password-1")
                .addPassword("alias2", "secret-password-2")
                .build();
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("THREE"))
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("secret_store_THREE")
                .addPassword("db-pass-1", "1-secret-info")
                .addPassword("db-pass-2", "2-secret-info")
                .addPassword("db-pass-3", "3-secret-info")
                .addPassword("db-pass-4", "4-secret-info")
                .addPassword("db-pass-5", "5-secret-info")
                .build();
    }

    /**
     * Remove security provider.
     */
    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    /**
     * After initialize Credential Store is removed backend CS file. This file must be created again when there is added new
     * entry to store.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     * @throws IOException
     */
    @Test
    public void testRecreatingKSTest()
        throws NoSuchAlgorithmException, CredentialStoreException, UnsupportedCredentialTypeException, IOException {

        Path ksPath = Paths.get(BASE_STORE_DIRECTORY, "ks.jceks");
        String storePassword = "storePassword";
        createAndCheckCredentialStoreStorageFile(ksPath, storePassword);

        char[] password1 = "secret-password1".toCharArray();
        char[] password2 = "secret-password2".toCharArray();

        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", ksPath.toAbsolutePath().toString());
        csAttributes.put("keyStoreType", "JCEKS");

        String passwordAlias1 = "passAlias1";
        String passwordAlias2 = "passAlias2";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, storePassword.toCharArray())))));

        cs.store(passwordAlias1, createCredentialFromPassword(password1));
        cs.store(passwordAlias2, createCredentialFromPassword(password2));

        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));

        if (!Files.deleteIfExists(ksPath)) {
            Assert.fail("KeyStore [" + ksPath.toAbsolutePath() + "] delete fail");
        }

        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        // load new entry (in memory)
        Assert.assertArrayEquals(password2, getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

        cs.store("abc", createCredentialFromPassword(password1));
        cs.flush();
        if (!Files.exists(ksPath)) {
            Assert.fail("KeyStore [" + ksPath.toAbsolutePath() + "] must exist yet.");
        }
    }

    /**
     * Credential Store is set to read-only.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     */
    @Test
    public void testReadOnly() throws NoSuchAlgorithmException, CredentialStoreException, UnsupportedCredentialTypeException {

        char[] password1 = "secret-password1".toCharArray();

        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("modifiable", "false");

        String passwordAlias1 = "passAlias_readonly";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray())))));

        try {
            cs.store(passwordAlias1, createCredentialFromPassword(password1));
            Assert.fail("This Credential Store should be read-only.");
        } catch (CredentialStoreException e) {

        }

        Assert.assertNull("'" + passwordAlias1 + "' must not be in this Credential Store because is read-only.",
            cs.retrieve(passwordAlias1, PasswordCredential.class));
    }

    /**
     * Credential Store entries must be case insensitive.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     */
    @Test
    public void testCaseInsensitiveAlias()
        throws NoSuchAlgorithmException, CredentialStoreException, UnsupportedCredentialTypeException {
        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray())))));

        // store test
        String caseSensitive1 = "caseSensitiveName";
        String caseSensitive2 = caseSensitive1.toUpperCase();
        char[] newPassword1 = "new-secret-passONE".toCharArray();
        char[] newPassword2 = "new-secret-passTWO".toCharArray();
        cs.store(caseSensitive1, createCredentialFromPassword(newPassword1));

        if (!cs.exists(caseSensitive1, PasswordCredential.class)) {
            Assert.fail("'" + caseSensitive1 + "'" + " must exist");
        }
        if (!cs.exists(caseSensitive1.toLowerCase(), PasswordCredential.class)) {
            Assert.fail("'" + caseSensitive1.toLowerCase() + "'" + " in lowercase must exist");
        }
        cs.remove(caseSensitive1, PasswordCredential.class);
        if (cs.exists(caseSensitive1, PasswordCredential.class)) {
            Assert.fail(caseSensitive1 + " has been removed from the vault, but it exists");
        }

        // this is actually alias update
        cs.store(caseSensitive2, createCredentialFromPassword(newPassword2));

        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive2, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1.toLowerCase(), PasswordCredential.class)));

        // Reaload CS keystore from filesystem
        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("modifiable", "false");

        CredentialStore csReloaded = newCredentialStoreInstance();
        csReloaded.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray())))));

        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive2, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1.toLowerCase(), PasswordCredential.class)));
    }

    /**
     * After initialize Credential Store is removed write permission on folder in which is stored CS file.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     * @throws IOException
     */
    @Test
    public void testNoWritePermissionToFolderUnixOs() throws Exception {
        Assume.assumeTrue(SystemUtils.IS_OS_UNIX);

        Path subfolderPath = Paths.get(BASE_STORE_DIRECTORY, "testNoWritePermissionToFolder");
        try {
            Path ksPath = subfolderPath.resolve("ks.jceks");
            String storePassword = "storePassword";
            createAndCheckCredentialStoreStorageFile(ksPath, storePassword);

            char[] password1 = "secret-password1".toCharArray();
            char[] password2 = "secret-password2".toCharArray();

            HashMap<String, String> csAttributes = new HashMap<>();

            csAttributes.put("location", ksPath.toAbsolutePath().toString());
            csAttributes.put("keyStoreType", "JCEKS");

            String passwordAlias1 = "passAlias1";
            String passwordAlias2 = "passAlias2";

            CredentialStore cs = newCredentialStoreInstance();
            cs.initialize(csAttributes,
                new CredentialStore.CredentialSourceProtectionParameter(
                    IdentityCredentials.NONE.withCredential(new PasswordCredential(
                        ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, storePassword.toCharArray())))));

            cs.store(passwordAlias1, createCredentialFromPassword(password1));
            cs.flush();
            Assert.assertArrayEquals(password1,
                getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));

            // change permissions
            setReadOnlyPermissions(subfolderPath);

            // this alias won't be persisted but it stays in memory CS
            cs.store(passwordAlias2, createCredentialFromPassword(password2));

            try {
                cs.flush();
                Assert.fail("It must fail because we don't have any write permission to folder.");
            } catch (CredentialStoreException e) {
                if (!"ELY09513: Unable to flush credential store to storage".equals(e.getMessage())) {
                    throw new RuntimeException(e);
                }
            }
        } finally {
            setAllPermissions(subfolderPath);
        }
    }

    /**
     * After initialize Credential Store is removed backed CS file. This file won't be created again when there is added new
     * entry to store because of no write permission to parent directory.
     *
     * @throws Exception
     */
    @Test
    public void testNoWritePermissionToFolderRecreatingKSTestUnixOs() throws Exception {
        Assume.assumeTrue(SystemUtils.IS_OS_UNIX);

        Path subfolderPath = Paths.get(BASE_STORE_DIRECTORY, "testNoWritePermissionToFolderRecreatingKSTest");
        try {
            Path ksPath = subfolderPath.resolve("ks.jceks");
            String storePassword = "storePassword";
            createAndCheckCredentialStoreStorageFile(ksPath, storePassword);

            char[] password1 = "secret-password1".toCharArray();
            char[] password2 = "secret-password2".toCharArray();

            HashMap<String, String> csAttributes = new HashMap<>();

            csAttributes.put("location", ksPath.toAbsolutePath().toString());
            csAttributes.put("keyStoreType", "JCEKS");

            String passwordAlias1 = "passAlias1";
            String passwordAlias2 = "passAlias2";

            CredentialStore cs = newCredentialStoreInstance();
            cs.initialize(csAttributes,
                new CredentialStore.CredentialSourceProtectionParameter(
                    IdentityCredentials.NONE.withCredential(new PasswordCredential(
                        ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, storePassword.toCharArray())))));

            cs.store(passwordAlias1, createCredentialFromPassword(password1));
            cs.store(passwordAlias2, createCredentialFromPassword(password2));

            Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));

            if (!Files.deleteIfExists(ksPath)) {
                Assert.fail("KeyStore [" + ksPath.toAbsolutePath() + "] delete fail");
            }

            // change permissions
            setReadOnlyPermissions(subfolderPath);

            Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
            // load new entry (in memory)
            Assert.assertArrayEquals(password2, getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

            cs.store("abc", createCredentialFromPassword(password1));
            try {
                cs.flush();
                Assert.fail("It must fail because we don't have any write permission to folder.");
            } catch (CredentialStoreException e) {
                if (!"ELY09513: Unable to flush credential store to storage".equals(e.getMessage())) {
                    throw new RuntimeException(e);
                }
            }
        } finally {
            setAllPermissions(subfolderPath);
        }
    }

    /**
     * After initialize Credential Store is removed backed CS file and his parent folder. This file must be created again when
     * there is added new entry to store.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     */
    @Test
    public void testRecreatingKSTestInNotExistsFolder() throws Exception {
        Path subfolderPath = Paths.get(BASE_STORE_DIRECTORY, "testRecreatingKSTestInNotExistsFolder");
        Path ksPath = subfolderPath.resolve("ks.jceks");
        String storePassword = "storePassword";
        createAndCheckCredentialStoreStorageFile(ksPath, storePassword);

        char[] password1 = "secret-password1".toCharArray();
        char[] password2 = "secret-password2".toCharArray();

        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", ksPath.toAbsolutePath().toString());
        csAttributes.put("keyStoreType", "JCEKS");

        String passwordAlias1 = "passAlias1";
        String passwordAlias2 = "passAlias2";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, storePassword.toCharArray())))));

        cs.store(passwordAlias1, createCredentialFromPassword(password1));
        cs.flush();
        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));

        if (!Files.deleteIfExists(ksPath)) {
            Assert.fail("KeyStore [" + ksPath.toAbsolutePath() + "] delete fail");
        }
        if (!Files.deleteIfExists(subfolderPath)) {
            Assert.fail(String.format("Delete folder [%s] failed.", subfolderPath.toAbsolutePath()));
        }

        cs.store(passwordAlias2, createCredentialFromPassword(password2));
        cs.flush();
        Assert.assertArrayEquals(password2, getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

        if (!Files.exists(ksPath)) {
            Assert.fail("KeyStore [" + ksPath.toAbsolutePath() + "] must exist yet.");
        }
    }

    /**
     * Basic {@code CredentialStore} test.
     * @throws Exception when problem occurs
     */
    @Test
    public void basicKeystorePasswordStoreTest() throws Exception {

        char[] password1 = "db-secret-pass1".toCharArray();
        char[] password2 = "PangmaŠišatá".toCharArray();
        char[] password3 = "Červenavý střizlíček a žľúva ďobali ve šťavnatých ocúnech".toCharArray();

        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("ONE"));
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("create", Boolean.TRUE.toString());

        String passwordAlias1 = "db1-password1";
        String passwordAlias2 = "db1-password2";
        String passwordAlias3 = "db1-password3";



        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes, new CredentialStore.CredentialSourceProtectionParameter(
            IdentityCredentials.NONE.withCredential(createCredentialFromPassword("test".toCharArray()))
        ));

        cs.store(passwordAlias1, createCredentialFromPassword(password1));
        cs.store(passwordAlias2, createCredentialFromPassword(password2));
        cs.store(passwordAlias3, createCredentialFromPassword(password3));
        cs.flush();

        Assert.assertArrayEquals(password2, getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));
        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        Assert.assertArrayEquals(password3, getPasswordFromCredential(cs.retrieve(passwordAlias3, PasswordCredential.class)));

        char[] newPassword1 = "new-secret-pass1".toCharArray();

        // update test
        cs.store(passwordAlias1, createCredentialFromPassword(newPassword1));
        Assert.assertArrayEquals(newPassword1,
            getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));

        // remove test
        cs.remove(passwordAlias2, PasswordCredential.class);

        if (cs.exists(passwordAlias2, PasswordCredential.class)) {
            Assert.fail(passwordAlias2 + " has been removed from the vault, but it exists");
        }
    }

    /**
     * Basic {@code CredentialStore} test on already existing store.
     * @throws Exception when problem occurs
     */
    @Test
    public void basicTestOnAlreadyCreatedKeystorePasswordStore() throws Exception {
        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");

        // testing if KeystorePasswordStore.MODIFIABLE default value is "true", so not setting anything

        String passwordAlias1 = "alias1";
        String passwordAlias2 = "alias2";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes, new CredentialStore.CredentialSourceProtectionParameter(
            IdentityCredentials.NONE.withCredential(
                new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray()))
            )
        ));

        // expected entries there
        Assert.assertArrayEquals("secret-password-1".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        Assert.assertArrayEquals("secret-password-2".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

        // retrieve non-existent entry
        Assert.assertNull(cs.retrieve("wrong_alias", PasswordCredential.class));

        // store test
        cs.store("db-password", createCredentialFromPassword("supersecretdbpass".toCharArray()));

        // remove test
        cs.remove(passwordAlias2, PasswordCredential.class);

        Set<String> aliases = cs.getAliases();
        Assert.assertFalse("Alias \"" + passwordAlias2 + "\" should be removed.", aliases.contains(passwordAlias2));

        if (!cs.exists("db-password", PasswordCredential.class)) {
            Assert.fail("'db-password'" + " has to exist");
        }

        if (cs.exists(passwordAlias2, PasswordCredential.class)) {
            Assert.fail(passwordAlias2 + " has been removed from the vault, but it exists");
        }

        char[] newPassword1 = "new-secret-pass1".toCharArray();

        // update test
        cs.store(passwordAlias1, createCredentialFromPassword(newPassword1));
        Assert.assertArrayEquals(newPassword1,
            getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
    }
}
