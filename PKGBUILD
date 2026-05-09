pkgname=reecanner-git
pkgver=1.0.0
pkgrel=1
pkgdesc="Fast TCP/UDP network scanner build with python and C worker, identify vulns with searchsploit. shodan like"
arch=('x86_64')
url="https://github.com/RshaCuDeVidro/REEcanner"
license=('MIT')
depends=('python' 'python-rich' 'python-redis')
makedepends=('git' 'make' 'python-setuptools')
source=("git+https://github.com/RshaCuDeVidro/REEcanner.git")
md5sums=('SKIP')

build() {
  cd "$srcdir/REEcanner"
  python setup.py build
}

package() {
  cd "$srcdir/REEcanner"
  python setup.py install --root="$pkgdir/" --optimize=1 --skip-build
}
