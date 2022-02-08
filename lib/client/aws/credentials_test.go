/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	awssdkv2http "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awssdkv2config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/trace"
)

func TestCredentialsFileProvider(t *testing.T) {
	tempDir := t.TempDir()
	credFilePath := path.Join(tempDir, "credentials")
	caFilePath := path.Join(tempDir, "ca.pem")
	config := &CredentialsConfig{
		AccessKeyID:       "access-id",
		SecretAccessKey:   "secret",
		CustomCABundePath: caFilePath,
	}
	require.NoError(t, config.CheckAndSetDefaults())

	// Prepare two certs in CA bundle file.
	entity := pkix.Name{CommonName: "credentials-ut", Organization: []string{"test"}}

	_, certPem, err := tlsca.GenerateSelfSignedCA(entity, []string{"localhost"}, time.Hour)
	require.NoError(t, err)
	_, expiredCertPem, err := tlsca.GenerateSelfSignedCA(entity, []string{"localhost"}, -time.Hour)
	require.NoError(t, err)

	pems := bytes.Join([][]byte{expiredCertPem, certPem}, []byte("\n"))
	require.NoError(t, os.WriteFile(caFilePath, pems, 0600))

	t.Run("SaveCredentialsFile", func(t *testing.T) {
		credProvider, err := SaveCredentialsFile(config, credFilePath)
		require.NoError(t, err)

		credValue, err := credProvider.Retrieve()
		require.NoError(t, err)
		require.Equal(t, credentials.Value{
			AccessKeyID:     "access-id",
			SecretAccessKey: "secret",
			ProviderName:    "teleport",
		}, credValue)
	})

	t.Run("LoadCredentialsFile", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			credProvider, err := LoadCredentialsFile(credFilePath, defaultProfile)
			require.NoError(t, err)

			require.False(t, credProvider.IsExpired())
			require.Equal(t, config.CustomCABundePath, credProvider.CustomCABundePath)

			credValue, err := credProvider.Retrieve()
			require.NoError(t, err)
			require.Equal(t, credentials.Value{
				AccessKeyID:     "access-id",
				SecretAccessKey: "secret",
				ProviderName:    "teleport",
			}, credValue)
		})

		t.Run("profile not found", func(t *testing.T) {
			_, err := LoadCredentialsFile(credFilePath, "missing_profile")
			require.True(t, trace.IsNotFound(err))
		})

		t.Run("path not found", func(t *testing.T) {
			_, err := LoadCredentialsFile("missing_file", defaultProfile)
			require.True(t, trace.IsNotFound(err))
		})
	})

	t.Run("environment variables", func(t *testing.T) {
		credProvider, err := LoadCredentialsFile(credFilePath, defaultProfile)
		require.NoError(t, err)

		credProvider.Setenv = func(key, value string) error {
			t.Setenv(key, value)
			return nil
		}

		t.Run("Get", func(t *testing.T) {
			envVars := credProvider.GetEnvironmentVariables()
			require.Equal(t, map[string]string{
				"AWS_ACCESS_KEY_ID":     "access-id",
				"AWS_SECRET_ACCESS_KEY": "secret",
				"AWS_CA_BUNDLE":         caFilePath,
			}, envVars)
		})

		t.Run("Set", func(t *testing.T) {
			err = credProvider.SetEnvironmentVariables()
			require.NoError(t, err)

			for key, value := range credProvider.GetEnvironmentVariables() {
				require.Equal(t, value, os.Getenv(key))
			}
		})

		t.Run("aws-sdk-go compatible", func(t *testing.T) {
			session, err := session.NewSession()
			require.NoError(t, err)

			// Verify access key and secret.
			credValue, err := session.Config.Credentials.Get()
			require.NoError(t, err)
			require.Equal(t, "access-id", credValue.AccessKeyID)
			require.Equal(t, "secret", credValue.SecretAccessKey)

			// Verify CA bundle.
			transport, ok := session.Config.HTTPClient.Transport.(*http.Transport)
			require.True(t, ok)

			verifyTransportWithRootCAs(t, transport, 2, entity.CommonName)
		})

		t.Run("aws-sdk-go-v2 compatible", func(t *testing.T) {
			config, err := awssdkv2config.LoadDefaultConfig(context.TODO())
			require.NoError(t, err)

			retrievedCredentials, err := config.Credentials.Retrieve(context.TODO())
			require.NoError(t, err)

			require.Equal(t, "access-id", retrievedCredentials.AccessKeyID)
			require.Equal(t, "secret", retrievedCredentials.SecretAccessKey)

			client, ok := config.HTTPClient.(*awssdkv2http.BuildableClient)
			require.True(t, ok)
			verifyTransportWithRootCAs(t, client.GetTransport(), 2, entity.CommonName)
		})
	})

	t.Run("AWS_SHARED_CREDENTIALS_FILE compatible", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "")
		t.Setenv("AWS_CA_BUNDLE", "")
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credFilePath)

		// Have to set Optionis.SharedConfigState to true or set environment
		// variable "AWS_SDK_LOAD_CONFIG" to true, for aws-sdk-go to use
		// "ca_bundle" from shared config.
		session, err := session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		})
		require.NoError(t, err)

		// Verify access key and secret.
		credValue, err := session.Config.Credentials.Get()
		require.NoError(t, err)
		require.Equal(t, "access-id", credValue.AccessKeyID)
		require.Equal(t, "secret", credValue.SecretAccessKey)

		// Verify CA bundle.
		transport, ok := session.Config.HTTPClient.Transport.(*http.Transport)
		require.True(t, ok)

		verifyTransportWithRootCAs(t, transport, 2, entity.CommonName)
	})
}

func verifyTransportWithRootCAs(t *testing.T, transport *http.Transport, numberOfCAs int, commonName string) {
	require.NotNil(t, transport)
	require.NotNil(t, transport.TLSClientConfig)
	require.NotNil(t, transport.TLSClientConfig.RootCAs)

	subjects := transport.TLSClientConfig.RootCAs.Subjects()
	require.Len(t, subjects, numberOfCAs)
	for _, subject := range subjects {
		require.Contains(t, string(subject), commonName)
	}
}
