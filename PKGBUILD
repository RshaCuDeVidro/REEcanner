pkgname=reecanner-git
pkgver=1.0.0
pkgrel=2
pkgdesc="Fast TCP/UDP network scanner build with python and C worker, identify vulns with searchsploit. shodan like"
arch=('x86_64')
url="https://github.com/RshaCuDeVidro/REEcanner"
license=('MIT')
depends=('python' 'python-rich' 'python-cryptography')
optdepends=('python-redis: push discovered hosts to a redis queue'
            'exploitdb: vulnerability lookup for discovered services (searchsploit)')
makedepends=('git' 'make' 'gcc' 'python-setuptools' 'python-build' 'python-installer' 'python-wheel')
source=("git+https://github.com/RshaCuDeVidro/REEcanner.git")
md5sums=('SKIP')

build() {
  cd "$srcdir/REEcanner"
  make
  python -m build --wheel --no-isolation
}

package() {
  cd "$srcdir/REEcanner"
  python -m installer --destdir="$pkgdir" dist/*.whl
}
