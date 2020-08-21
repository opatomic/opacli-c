
opatlsSetVars() {
	OPA_MBEDTLS="${OPA_MBEDTLS:-1}"
	OPA_OPENSSL="${OPA_OPENSSL:-0}"
	OPA_OPENSSL_DL="${OPA_OPENSSL_DL:-1}"
	if [ "$TGTOS" = "win" ]; then
		OPA_WINSCHAN="${OPA_WINSCHAN:-0}"
	else
		OPA_WINSCHAN="${OPA_WINSCHAN:-0}"
	fi
	if [ "$TGTOS" = "darwin" ]; then
		OPA_SECTRANS="${OPA_SECTRANS:-0}"
	else
		OPA_SECTRANS="${OPA_SECTRANS:-0}"
	fi

	OPATLS_DEFS=""
	OPATLS_LNLIBS=""
	OPATLS_LDFLAGS=""
	if [ "$OPA_OPENSSL" != "0" ]; then
		OPATLS_DEFS="$OPATLS_DEFS -DOPA_OPENSSL"
		if [ "$OPA_OPENSSL_DL" != "0" ]; then
			OPATLS_DEFS="$OPATLS_DEFS -DOPA_OPENSSL_DL"
		fi
	fi
	if [ "$OPA_MBEDTLS" != "0" ]; then
		if [ -z "$MBEDTLS_DIR" ]; then
			echo '$MBEDTLS_DIR must be set'
			exit 1
		fi
		OPATLS_DEFS="$OPATLS_DEFS -DOPA_MBEDTLS"
		OPATLS_LNLIBS="$OPATLS_LNLIBS $MBEDTLS_DIR/library/libmbedtls.a"
		OPATLS_LNLIBS="$OPATLS_LNLIBS $MBEDTLS_DIR/library/libmbedx509.a"
		OPATLS_LNLIBS="$OPATLS_LNLIBS $MBEDTLS_DIR/library/libmbedcrypto.a"
	fi
	if [ "$OPA_WINSCHAN" != "0" ]; then
		OPATLS_DEFS="$OPATLS_DEFS -DOPA_WINSCHAN"
	fi
	if [ "$OPA_SECTRANS" != "0" ]; then
		OPATLS_DEFS="$OPATLS_DEFS -DOPA_SECTRANS"
	fi
	if [ "$TGTOS" = "linux" ] || [ "$TGTOS" = "freebsd" ]; then
		if [ "$OPA_OPENSSL" != "0" ] && [ "$OPA_OPENSSL_DL" = "0" ]; then
			OPATLS_LNLIBS="$OPATLS_LNLIBS -l:libssl.so.1.1 -l:libcrypto.so.1.1"
		fi
		OPATLS_LNLIBS="$OPATLS_LNLIBS -ldl"
	fi

	if [ "$TGTOS" = "win" ]; then
		if [ "$OPA_MBEDTLS" != "0" ] || [ "$OPA_WINSCHAN" != "0" ]; then
			OPATLS_LNLIBS="$OPATLS_LNLIBS -lcrypt32"
		fi
	fi
	if [ "$TGTOS" = "darwin" ]; then
		if [ "$OPA_MBEDTLS" != "0" ] || [ "$OPA_SECTRANS" != "0" ]; then
			# note: if a warning about text-based stub file is out of sync, try this:
			#  https://stackoverflow.com/a/53111739
			#  sudo ln -s  /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/CoreFoundation.framework /Library/Frameworks/CoreFoundation.framework
			#  sudo ln -s  /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Security.framework /Library/Frameworks/Security.framework
			OPATLS_LDFLAGS="$OPATLS_LDFLAGS -framework CoreFoundation -framework Security"
		fi
	fi
}

buildmbedtls() {
	if [ "$OPA_MBEDTLS" = "0" ]; then
		return
	fi

	if [ -z "$MBEDTLS_DIR" ] || [ -z "$MBEDTLS_BRANCH" ] || [ -z "$MBEDTLS_CONFIG_FILE" ]; then
		echo '$MBEDTLS_DIR and $MBEDTLS_BRANCH and $MBEDTLS_CONFIG_FILE must be set'
		exit 1
	fi

	if [ ! -f "$MBEDTLS_CONFIG_FILE" ]; then
		echo '$MBEDTLS_CONFIG_FILE file does not exist'
		exit 1
	fi

	ORIGDIR=$(pwd)

	if [ -d "$MBEDTLS_DIR" ]; then
		if [ "$(git -C "$MBEDTLS_DIR" rev-parse --abbrev-ref HEAD)" != "$MBEDTLS_BRANCH" ]; then
			# if mbedtls git branch is wrong then delete directory and start over
			rm -rf "$MBEDTLS_DIR"
		fi
	fi

	if [ ! -d "$MBEDTLS_DIR" ]; then
		# get mbedtls dependency if needed
		mkdir -p "$MBEDTLS_DIR"
		git clone --single-branch --depth 1 --branch "$MBEDTLS_BRANCH" "https://github.com/ARMmbed/mbedtls.git" "$MBEDTLS_DIR"
	fi
	cd "$MBEDTLS_DIR" || exit 1
	git clean -fd
	git checkout -- .
	git pull
	cd "$ORIGDIR" || exit 1
	cp "$MBEDTLS_CONFIG_FILE" "$MBEDTLS_DIR/include/mbedtls/config.h" || exit 1
	cd "$MBEDTLS_DIR" || exit 1
	make clean
	make CFLAGS="$CFLAGS" -j $NPROC lib
	cd "$ORIGDIR" || exit 1
}
