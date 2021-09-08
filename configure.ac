AC_INIT([Haskell xml signature library], [0.1.0.0], [james.hobson@jotron.com], [xml-verify])

# Safety check: Ensure that we are in the correct source directory.
AC_CONFIG_SRCDIR([xml-verify.cabal])

# Check for lib xmlsec on the system
PKG_CHECK_MODULES(XMLSEC, xmlsec1 >= 1.0.0,,exit)
CFLAGS="$CFLAGS $XMLSEC_CFLAGS"
LDFLAGS="$LDFLAGS $XMLSEC_LIBS"

AC_SUBST([CFLAGS])
AC_SUBST([LDFLAGS])

# Build the package if we found X11 stuff
AC_CONFIG_FILES([xml-verify.buildinfo])
AC_OUTPUT
