const helpers = (obj) => Object.entries(obj).map(([key, value]) => {
    if (value == null || value  == '' || value == undefined) {
        throw `${key} is required.`
    }
})

function validateInput(field, fieldName) {
    if (!field) {
        return res.send({ message: `${fieldName} is required.` });
    }
}

module.exports = helpers;