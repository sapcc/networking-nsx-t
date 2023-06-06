# https://github.com/StackStorm-Exchange/stackstorm-vault/pull/23#issuecomment-860846298
from urllib3.contrib import pyopenssl
pyopenssl.inject_into_urllib3()