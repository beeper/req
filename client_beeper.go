package req

import (
	utls "github.com/refraction-networking/utls"

	"github.com/imroc/req/v3/http2"
)

var (
	instagramAndroidHttp2Settings = []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 163840},
	}
)

func makeInstagramAndroidTLSFingerprint() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS13,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       []uint16{utls.TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA256,
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2"}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModePlain, utls.PskModeDHE}},
		},
	}
}

func (c *Client) ImpersonateInstagramAndroid() *Client {
	c.
		SetHTTP2SettingsFrame(instagramAndroidHttp2Settings...).
		SetHTTP2ConnectionFlow(2031617).
		SetCommonPseudoHeaderOder(":authority", ":method", ":path", ":scheme").
		setTLSFingerprint(utls.HelloCustom, func(conn *uTLSConn) error {
			err := conn.ApplyPreset(makeInstagramAndroidTLSFingerprint())
			if err != nil {
				return err
			}
			conn.HandshakeState.Hello.SessionId = nil
			return nil
		})
	return c
}
