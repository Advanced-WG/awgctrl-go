sed -i '' '/I5:   strPtr("<r 14>"),/a \
		HeaderProtectionKey: keyPtr(wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),\
		ContentPaddingAddition: intPtr(5),\
		RekeyAfterTime: intPtr(10),\
		RekeyTimeout: intPtr(15),\
		RejectAfterTime: intPtr(20),\
		KeepaliveTimeout: intPtr(25),\
		MaxHandshakeAttempts: intPtr(30),\
		RandomTrailers: boolPtr(true),\
		DisableCookies: boolPtr(true),
' internal/wglinux/configure_linux_test.go
