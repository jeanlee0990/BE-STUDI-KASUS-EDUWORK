const { getToken, policyFor } = require('../utils');
const jwt = require('jsonwebtoken');
const config = require('../app/config');
const User = require('../app/user/model');

function decodeToken() {
    return async function (req, res, next) {
        try {
            let token = getToken(req);

            if (!token) return next(); // ngelanjutin kalo gk ada token

            req.user = jwt.verify(token, config.secretkey);

            let user = await User.findOne({ token: { $in: [token] } });

            if (!user) {
                return res.json({
                    error: 1,
                    message: 'Token Expired',
                });
            }
            // ngelanjutin kalo token valid dan user ditemukan
            return next();
        } catch (err) {
            // Tambahkan parameter err untuk menangani kesalahan
            if (err && err.name === 'JsonWebTokenError') {
                return res.json({
                    error: 1,
                    message: err.message,
                });
            }
            next(err); // Panggil next(err) untuk antisipasi kesalahan lainnya
        }
    };
}

//middleware buat cek hak akses
function police_check(action, subject) {
    return function (req, res, next) {
        let policy = policyFor(req.user);
        if (!policy.can(action, subject)) {
            return res.json({
                error: 1,
                messages: `You are not allowed to ${action} ${subject}`,
            });
        }
        next();
    };
}

module.exports = {
    decodeToken,
    police_check,
};
