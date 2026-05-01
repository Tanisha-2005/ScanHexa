const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    scanId: {
        type: String,
        required: true,
        unique: true
    },
    target: {
        type: String,
        required: true
    },
    user: {
        type: String,
        required: true
    },
    data: {
        type: Object,
        required: true
    },
    riskAssessment: {
        level: String,
        score: Number
    },
    success: {
        type: Boolean,
        default: true
    }
}, { timestamps: true });

module.exports = mongoose.model('Report', reportSchema);
