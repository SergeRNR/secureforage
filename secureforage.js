'use strict';

window.secureforage = (function(){
    var config = { delimiter: '.$$' },
        pwd;

    var _deriveKey = function (pass, salt) {
        return CryptoJS.PBKDF2(pass, salt, { keySize: 256/32 });
    };

    var _retrievePWKey = function (key, salt) {
        var pass = pwd || prompt('Please enter your password');

        if (!pass) {
            Promise.reject(null);
        } else {
            pwd = pass;
        }

        if (salt) {
            return Promise.resolve(_deriveKey(pass, salt));
        }

        return _getSalt(key).then(function (salt) {
            return _deriveKey(pass, salt);
        });
    };

    var _getSalt = function (key) {
        key = key + config.delimiter + 'salt';

        return localforage.getItem(key).then(function (salt) {
            if (salt) {
                return salt;
            }

            var salt = CryptoJS.lib.WordArray.random(16).toString();
            return localforage.setItem(key, salt);
        });
    };

    // API methods

    var getItem = function (key) {
        var values = Promise.all([
            localforage.getItem(key),
            localforage.getItem(key + config.delimiter + 'salt')
        ]);

        return values.then(function (values) {
            var data = values[0];
            var salt = values[1];
            if (!data || !salt) {
                return null;
            }

            return _retrievePWKey(key, salt).then(function (cryptoKey) {
                var decrypted = CryptoJS.AES.decrypt(data, cryptoKey.toString());
                decrypted = decrypted.toString(CryptoJS.enc.Utf8);

                if (!decrypted) {
                    throw 'Invalid pasword';
                } else {
                    return JSON.parse(decrypted);
                }
            });
        });
    };

    var setItem = function (key, data) {
        return _retrievePWKey(key).then(function (cryptoKey) {
            var encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), cryptoKey.toString());
            return localforage.setItem(key, encrypted.toString());
        });
    };

    var removeItem = function (key, cb) {
        return getItem(key).then(function (data) {
            return Promise.all([
                localforage.removeItem(key),
                localforage.removeItem(key + config.delimiter + 'salt')
            ]);
        });
    };

    var clear = function (cb) {
        return localforage.clear(cb);
    };

    (function init () {
        pwd = prompt('Please enter your password');
    })();

    return {
        getItem: getItem,
        setItem: setItem,
        removeItem: removeItem,
        clear: clear
    };
})();
