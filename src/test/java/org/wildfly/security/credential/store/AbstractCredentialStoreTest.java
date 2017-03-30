/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.SystemUtils;
import org.jboss.logging.Logger;
import org.junit.Assert;

public class AbstractCredentialStoreTest {

    private static Logger log = Logger.getLogger(AbstractCredentialStoreTest.class);

    protected void createAndCheckCredentialStoreStorageFile(Path keyStorePath, String storePassword) {
        try {
            CredentialStoreBuilder.get().setKeyStoreFile(keyStorePath.toAbsolutePath().toString())
            .setKeyStorePassword(storePassword)
            .addPassword("dummy_alias_1", "secret-password-1")
            .build();
            if (!Files.exists(keyStorePath) && Files.isReadable(keyStorePath)) {
                Assert.fail("KeyStore must exists!");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected static void setReadOnlyPermissions(Path filePath) throws Exception {
        if (Files.exists(filePath)) {
            if (SystemUtils.IS_OS_UNIX) {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);

                setPermissionsUnix(filePath, perms);
            } else if (SystemUtils.IS_OS_WINDOWS) {
                ProcessBuilder p = new ProcessBuilder();
                p.command("whoami");
                Process process = p.start();
                boolean waitFor = process.waitFor(3, TimeUnit.SECONDS);
                String user = output(process.getInputStream()).trim();
                log.info(String.format("Process finished [%s], output [%s]", waitFor, user));

                p = new ProcessBuilder();
                p.command("icacls", "\"" + filePath.toAbsolutePath() + "\"", "/remove:g", user, "/t");
                process = p.start();
                waitFor = process.waitFor(10, TimeUnit.SECONDS);
                log.info(String.format("Process finished [%s], output [%s]", waitFor, output(process.getInputStream())));

                p = new ProcessBuilder();
                p.command("icacls", "\"" + filePath.toAbsolutePath() + "\"", "/deny", String.format("\"%s:(OI)(CI)(IO)(F)\"", user), "/t");
                process = p.start();
                waitFor = process.waitFor(3, TimeUnit.SECONDS);
                log.info(String.format("Process finished [%s], output [%s]", waitFor, output(process.getInputStream())));
            }
        }
    }

    private static String output(InputStream inputStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(inputStream));
            String line = null;
            while ((line = br.readLine()) != null) {
                sb.append(line + System.getProperty("line.separator"));
            }
        } finally {
            br.close();
        }
        return sb.toString();
    }

    protected static void setAllPermissions(Path filePath) {
        if (Files.exists(filePath)) {
            if (SystemUtils.IS_OS_UNIX) {
                Set<PosixFilePermission> perms = new HashSet<>();
                for (PosixFilePermission posixFilePermission : PosixFilePermission.values()) {
                    perms.add(posixFilePermission);
                }
                setPermissionsUnix(filePath, perms);
            } else if (SystemUtils.IS_OS_WINDOWS) {
                setPermissionsWin(filePath, true);
            }
        }
    }

    private static void setPermissionsUnix(Path filePath, Set<PosixFilePermission> permissions) {
        if (Files.exists(filePath)) {
            if (SystemUtils.IS_OS_UNIX) {
                try {
                    Files.setPosixFilePermissions(filePath, permissions);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                throw new IllegalStateException("Unix like OS is expected.");
            }
        }
    }

    private static void setPermissionsWin(Path filePath, boolean readonly) {
        if (Files.exists(filePath)) {
            if (SystemUtils.IS_OS_WINDOWS) {
                filePath.toFile().setWritable(readonly, false);
            } else {
                throw new IllegalStateException("Windows OS is expected.");
            }
        }
    }

    public AbstractCredentialStoreTest() {
        super();
    }

}