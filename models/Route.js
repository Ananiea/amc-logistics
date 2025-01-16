const mongoose = require("mongoose");

const RouteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: String,
    date: { type: Date, required: true },
    auto: String,
    tour: Number,
    kunde: Number,
    start: String,
    ende: String,
    totalTourMontliche: Number,
});

module.exports = mongoose.model("Route", RouteSchema);
