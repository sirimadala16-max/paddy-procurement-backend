// =========================================================
// LOAD ENVIRONMENT VARIABLES
// =========================================================

require("dotenv").config();


// =========================================================
// IMPORT PACKAGES
// =========================================================

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const jsforce = require("jsforce");


// =========================================================
// CREATE EXPRESS APP
// =========================================================

const app = express();


// =========================================================
// TRUST PROXY
// =========================================================

// Required when running behind Render's proxy.

app.set("trust proxy", 1);


// =========================================================
// SECURITY CONFIGURATION
// =========================================================

const ALLOWED_ORIGINS = [

    "https://sirimadala16-max.github.io",

    "http://localhost:3000",

    "http://127.0.0.1:3000"

];


// =========================================================
// SECURITY MIDDLEWARE
// =========================================================

// Add secure HTTP headers.

app.use(
    helmet()
);


// =========================================================
// CORS CONFIGURATION
// =========================================================

app.use(
    cors({

        origin: function (origin, callback) {

            // Allow requests without an Origin header.
            // Useful for direct API access and server-side tools.

            if (!origin) {

                return callback(null, true);

            }


            if (
                ALLOWED_ORIGINS.includes(origin)
            ) {

                return callback(null, true);

            }


            return callback(
                new Error("CORS policy: Origin not allowed.")
            );

        },

        methods: [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type"
        ]

    })
);


// =========================================================
// REQUEST BODY LIMIT
// =========================================================

app.use(
    express.json({
        limit: "100kb"
    })
);


// =========================================================
// RATE LIMITERS
// =========================================================

// Protect Salesforce authentication endpoints.

const authLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            10,

        standardHeaders:
            true,

        legacyHeaders:
            false,

        message: {

            error:
                "Too many authentication attempts. Please try again later."

        }

    });


// Protect application APIs.

const apiLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            300,

        standardHeaders:
            true,

        legacyHeaders:
            false,

        message: {

            error:
                "Too many requests. Please try again later."

        }

    });


// Apply API rate limiter.

app.use(
    "/api",
    apiLimiter
);


// =========================================================
// SALESFORCE CONFIGURATION
// =========================================================

const SALESFORCE_CLIENT_ID =
    process.env.SALESFORCE_CLIENT_ID;

const SALESFORCE_CLIENT_SECRET =
    process.env.SALESFORCE_CLIENT_SECRET;

const SALESFORCE_LOGIN_URL =
    process.env.SALESFORCE_LOGIN_URL;

const SALESFORCE_CALLBACK_URL =
    process.env.SALESFORCE_CALLBACK_URL;


// =========================================================
// ENVIRONMENT VALIDATION
// =========================================================

const requiredEnvironmentVariables = [

    "SALESFORCE_CLIENT_ID",

    "SALESFORCE_CLIENT_SECRET",

    "SALESFORCE_LOGIN_URL",

    "SALESFORCE_CALLBACK_URL"

];


const missingEnvironmentVariables =
    requiredEnvironmentVariables.filter(
        (variable) =>
            !process.env[variable]
    );


if (
    missingEnvironmentVariables.length > 0
) {

    console.error(
        "Missing required environment variables:",
        missingEnvironmentVariables.join(", ")
    );

    process.exit(1);

}


// =========================================================
// OAUTH VARIABLES
// =========================================================

// Temporary OAuth state values.
//
// NOTE:
// These are intentionally stored only in memory for now.
// We will improve authentication persistence in a later step.

let oauthState = null;

let codeVerifier = null;

let salesforceConnection = null;


// =========================================================
// HELPER FUNCTIONS
// =========================================================


// ---------------------------------------------------------
// CHECK SALESFORCE CONNECTION
// ---------------------------------------------------------

function requireSalesforceConnection(req, res, next) {

    if (!salesforceConnection) {

        return res
            .status(401)
            .json({

                error:
                    "Not connected to Salesforce. Please login first."

            });

    }

    next();

}


// ---------------------------------------------------------
// VALIDATE SALESFORCE RECORD ID
// ---------------------------------------------------------

function isValidSalesforceId(id) {

    return (
        typeof id === "string" &&
        /^[a-zA-Z0-9]{15}(?:[a-zA-Z0-9]{3})?$/.test(id)
    );

}


// ---------------------------------------------------------
// VALIDATE POSITIVE NUMBER
// ---------------------------------------------------------

function isPositiveNumber(value) {

    return (
        value !== undefined &&
        value !== null &&
        value !== "" &&
        Number.isFinite(Number(value)) &&
        Number(value) > 0
    );

}


// ---------------------------------------------------------
// VALIDATE NON-NEGATIVE NUMBER
// ---------------------------------------------------------

function isNonNegativeNumber(value) {

    return (
        value !== undefined &&
        value !== null &&
        value !== "" &&
        Number.isFinite(Number(value)) &&
        Number(value) >= 0
    );

}


// =========================================================
// HOME ROUTE
// =========================================================

app.get("/", (req, res) => {

    res.send(`

        <!DOCTYPE html>

        <html>

        <head>

            <title>
                Paddy Procurement Backend
            </title>

        </head>

        <body>

            <h1>
                Paddy Procurement Backend
            </h1>

            <p>
                Backend is running successfully.
            </p>

            <p>
                <a href="/auth/login">
                    Login with Salesforce
                </a>
            </p>

        </body>

        </html>

    `);

});


// =========================================================
// SALESFORCE LOGIN
// =========================================================

app.get(
    "/auth/login",
    authLimiter,
    (req, res) => {

        try {

            // Generate OAuth state.

            oauthState =
                crypto
                    .randomBytes(32)
                    .toString("hex");


            // Generate PKCE code verifier.

            codeVerifier =
                crypto
                    .randomBytes(32)
                    .toString("base64url");


            // Generate PKCE code challenge.

            const codeChallenge =
                crypto
                    .createHash("sha256")
                    .update(codeVerifier)
                    .digest("base64url");


            // Create Salesforce OAuth2 object.

            const oauth2 =
                new jsforce.OAuth2({

                    loginUrl:
                        SALESFORCE_LOGIN_URL,

                    clientId:
                        SALESFORCE_CLIENT_ID,

                    clientSecret:
                        SALESFORCE_CLIENT_SECRET,

                    redirectUri:
                        SALESFORCE_CALLBACK_URL

                });


            // Generate Salesforce authorization URL.

            const authUrl =
                oauth2.getAuthorizationUrl({

                    state:
                        oauthState,

                    scope:
                        "api web refresh_token",

                    prompt:
                        "login",

                    code_challenge:
                        codeChallenge,

                    code_challenge_method:
                        "S256"

                });


            console.log(
                "Redirecting to Salesforce login..."
            );


            res.redirect(authUrl);

        }

        catch (error) {

            console.error(
                "Salesforce login error:",
                error
            );

            res
                .status(500)
                .send(
                    "Unable to start Salesforce login."
                );

        }

    }
);


// =========================================================
// SALESFORCE OAUTH CALLBACK
// =========================================================

app.get(
    "/oauth/callback",
    async (req, res) => {

        try {

            const {
                code,
                state
            } = req.query;


            // -------------------------------------------------
            // CHECK STATE
            // -------------------------------------------------

            if (
                !state ||
                !oauthState ||
                state !== oauthState
            ) {

                return res
                    .status(400)
                    .send(
                        "Invalid OAuth state."
                    );

            }


            // -------------------------------------------------
            // CHECK AUTHORIZATION CODE
            // -------------------------------------------------

            if (!code) {

                return res
                    .status(400)
                    .send(
                        "Authorization code missing."
                    );

            }


            // -------------------------------------------------
            // CHECK PKCE VERIFIER
            // -------------------------------------------------

            if (!codeVerifier) {

                return res
                    .status(400)
                    .send(
                        "OAuth verification data is missing."
                    );

            }


            // -------------------------------------------------
            // CREATE OAUTH2 OBJECT
            // -------------------------------------------------

            const oauth2 =
                new jsforce.OAuth2({

                    loginUrl:
                        SALESFORCE_LOGIN_URL,

                    clientId:
                        SALESFORCE_CLIENT_ID,

                    clientSecret:
                        SALESFORCE_CLIENT_SECRET,

                    redirectUri:
                        SALESFORCE_CALLBACK_URL

                });


            // -------------------------------------------------
            // EXCHANGE AUTHORIZATION CODE
            // -------------------------------------------------

            console.log(
                "Exchanging authorization code for token..."
            );


            const token =
                await oauth2.requestToken(
                    code,
                    {

                        code_verifier:
                            codeVerifier

                    }
                );


            console.log(
                "Salesforce token received successfully."
            );


            // -------------------------------------------------
            // CREATE AUTHENTICATED SALESFORCE CONNECTION
            // -------------------------------------------------

            salesforceConnection =
                new jsforce.Connection({

                    instanceUrl:
                        token.instance_url,

                    accessToken:
                        token.access_token,

                    refreshToken:
                        token.refresh_token,

                    oauth2:
                        oauth2

                });


            console.log(
                "Salesforce connection created successfully."
            );


            // -------------------------------------------------
            // RESET TEMPORARY OAUTH VALUES
            // -------------------------------------------------

            oauthState = null;

            codeVerifier = null;


            // -------------------------------------------------
            // SUCCESS RESPONSE
            // -------------------------------------------------

            res.send(`

                <!DOCTYPE html>

                <html>

                <head>

                    <title>
                        Salesforce Login Successful
                    </title>

                    <style>

                        body {

                            font-family:
                                Arial, sans-serif;

                            background:
                                #f4f7fb;

                            display:
                                flex;

                            justify-content:
                                center;

                            align-items:
                                center;

                            min-height:
                                100vh;

                            margin:
                                0;

                        }

                        .box {

                            background:
                                white;

                            padding:
                                40px;

                            border-radius:
                                12px;

                            box-shadow:
                                0 5px 20px
                                rgba(0,0,0,0.1);

                            text-align:
                                center;

                        }

                        h1 {

                            color:
                                #2e7d32;

                        }

                        p {

                            color:
                                #555;

                        }

                    </style>

                </head>


                <body>

                    <div class="box">

                        <h1>
                            Salesforce Login Successful! 🎉
                        </h1>

                        <p>
                            OAuth 2.0 authentication is working.
                        </p>

                        <p>
                            Your Paddy Procurement backend
                            is now connected to Salesforce.
                        </p>

                        <p>
                            You can close this tab and
                            return to your application.
                        </p>

                    </div>

                </body>

                </html>

            `);

        }

        catch (error) {

            console.error(
                "OAuth callback error:",
                error
            );

            res
                .status(500)
                .send(`

                    <h1>
                        Salesforce authentication failed.
                    </h1>

                    <p>
                        Please check the backend logs
                        for the exact error.
                    </p>

                `);

        }

    }
);


// =========================================================
// FARMER APIs
// =========================================================


// =========================================================
// GET ALL FARMERS
// =========================================================

app.get(
    "/api/farmers",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const result =
                await salesforceConnection.query(`

                    SELECT
                        Id,
                        Name,
                        Phone__c,
                        Address__c

                    FROM Farmer__c

                    ORDER BY CreatedDate DESC

                `);


            res.json(
                result.records
            );

        }

        catch (error) {

            console.error(
                "Salesforce farmer error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to retrieve farmers."

                });

        }

    }
);


// =========================================================
// ADD FARMER
// =========================================================

app.post(
    "/api/farmers",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const {
                name,
                phone,
                address
            } = req.body;


            // Validate name.

            if (
                typeof name !== "string" ||
                name.trim() === ""
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Farmer name is required."

                    });

            }


            // Validate phone.

            if (
                typeof phone !== "string" ||
                !/^\d{10}$/.test(phone)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Phone number must contain exactly 10 digits."

                    });

            }


            // Validate address.

            if (
                typeof address !== "string" ||
                address.trim() === ""
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Address is required."

                    });

            }


            // Create Salesforce record.

            const result =
                await salesforceConnection
                    .sobject("Farmer__c")
                    .create({

                        Name:
                            name.trim(),

                        Phone__c:
                            phone,

                        Address__c:
                            address.trim()

                    });


            console.log(
                "Farmer created:",
                result
            );


            if (!result.success) {

                return res
                    .status(500)
                    .json({

                        error:
                            "Failed to create farmer in Salesforce."

                    });

            }


            res
                .status(201)
                .json({

                    message:
                        "Farmer added successfully.",

                    id:
                        result.id

                });

        }

        catch (error) {

            console.error(
                "Add farmer error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to add farmer to Salesforce."

                });

        }

    }
);


// =========================================================
// UPDATE FARMER
// =========================================================

app.put(
    "/api/farmers/:id",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const farmerId =
                req.params.id;


            const {
                name,
                phone,
                address
            } = req.body;


            // Validate Salesforce ID.

            if (
                !isValidSalesforceId(farmerId)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Invalid Salesforce farmer ID."

                    });

            }


            // Validate name.

            if (
                typeof name !== "string" ||
                name.trim() === ""
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Farmer name is required."

                    });

            }


            // Validate phone.

            if (
                typeof phone !== "string" ||
                !/^\d{10}$/.test(phone)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Phone number must contain exactly 10 digits."

                    });

            }


            // Validate address.

            if (
                typeof address !== "string" ||
                address.trim() === ""
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Address is required."

                    });

            }


            const result =
                await salesforceConnection
                    .sobject("Farmer__c")
                    .update({

                        Id:
                            farmerId,

                        Name:
                            name.trim(),

                        Phone__c:
                            phone,

                        Address__c:
                            address.trim()

                    });


            console.log(
                "Farmer updated:",
                result
            );


            if (!result.success) {

                return res
                    .status(500)
                    .json({

                        error:
                            "Failed to update farmer in Salesforce."

                    });

            }


            res.json({

                message:
                    "Farmer updated successfully.",

                id:
                    farmerId

            });

        }

        catch (error) {

            console.error(
                "Update farmer error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to update farmer in Salesforce."

                });

        }

    }
);


// =========================================================
// DELETE FARMER
// =========================================================

app.delete(
    "/api/farmers/:id",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const farmerId =
                req.params.id;


            if (
                !isValidSalesforceId(farmerId)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Invalid Salesforce farmer ID."

                    });

            }


            const result =
                await salesforceConnection
                    .sobject("Farmer__c")
                    .delete(
                        farmerId
                    );


            console.log(
                "Farmer deleted:",
                result
            );


            if (!result.success) {

                return res
                    .status(500)
                    .json({

                        error:
                            "Failed to delete farmer from Salesforce."

                    });

            }


            res.json({

                message:
                    "Farmer deleted successfully.",

                id:
                    farmerId

            });

        }

        catch (error) {

            console.error(
                "Delete farmer error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to delete farmer from Salesforce."

                });

        }

    }
);


// =========================================================
// PROCUREMENT APIs
// =========================================================


// =========================================================
// GET ALL PROCUREMENT RECORDS
// =========================================================

app.get(
    "/api/procurements",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const result =
                await salesforceConnection.query(`

                    SELECT
                        Id,
                        Name,
                        Farmer__c,
                        Farmer__r.Name,
                        Procurement_Date__c,
                        Gross_Weight__c,
                        Bag_Deduction__c,
                        Weighbridge_Deduction__c,
                        Net_Weight__c,
                        Final_Bags__c,
                        Paddy_Rate__c,
                        Total_Amount__c

                    FROM Paddy_Procurement__c

                    ORDER BY Procurement_Date__c DESC

                `);


            res.json(
                result.records
            );

        }

        catch (error) {

            console.error(
                "Salesforce procurement error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to retrieve procurement records."

                });

        }

    }
);


// =========================================================
// GET SINGLE PROCUREMENT BY ID
// =========================================================

app.get(
    "/api/procurements/:id",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const procurementId =
                req.params.id;


            // Validate Salesforce ID before
            // placing it inside the SOQL query.

            if (
                !isValidSalesforceId(procurementId)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Invalid Salesforce procurement ID."

                    });

            }


            const result =
                await salesforceConnection.query(`

                    SELECT
                        Id,
                        Name,
                        Farmer__c,
                        Farmer__r.Name,
                        Procurement_Date__c,
                        Gross_Weight__c,
                        Bag_Deduction__c,
                        Weighbridge_Deduction__c,
                        Net_Weight__c,
                        Final_Bags__c,
                        Paddy_Rate__c,
                        Total_Amount__c

                    FROM Paddy_Procurement__c

                    WHERE Id = '${procurementId}'

                    LIMIT 1

                `);


            if (
                !result.records ||
                result.records.length === 0
            ) {

                return res
                    .status(404)
                    .json({

                        error:
                            "Procurement record not found."

                    });

            }


            res.json(
                result.records[0]
            );

        }

        catch (error) {

            console.error(
                "Single procurement error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to retrieve procurement record."

                });

        }

    }
);


// =========================================================
// ADD PROCUREMENT
// =========================================================

app.post(
    "/api/procurements",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const {
                farmerId,
                procurementDate,
                grossWeight,
                bagDeduction,
                paddyRate
            } = req.body;


            // Validate farmer ID.

            if (
                !isValidSalesforceId(farmerId)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "A valid farmer ID is required."

                    });

            }


            // Validate procurement date.

            if (
                typeof procurementDate !== "string" ||
                procurementDate.trim() === ""
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Procurement date is required."

                    });

            }


            // Validate gross weight.

            if (
                !isPositiveNumber(grossWeight)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Gross weight must be greater than 0."

                    });

            }


            // Validate bag deduction.

            if (
                !isNonNegativeNumber(bagDeduction)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Bag deduction cannot be negative."

                    });

            }


            // Validate paddy rate.

            if (
                !isPositiveNumber(paddyRate)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Paddy rate must be greater than 0."

                    });

            }


            // Create Salesforce record.

            const result =
                await salesforceConnection
                    .sobject(
                        "Paddy_Procurement__c"
                    )
                    .create({

                        Farmer__c:
                            farmerId,

                        Procurement_Date__c:
                            procurementDate,

                        Gross_Weight__c:
                            Number(grossWeight),

                        Bag_Deduction__c:
                            Number(bagDeduction),

                        Paddy_Rate__c:
                            Number(paddyRate)

                    });


            console.log(
                "Procurement created:",
                result
            );


            if (!result.success) {

                return res
                    .status(500)
                    .json({

                        error:
                            "Failed to create procurement in Salesforce."

                    });

            }


            res
                .status(201)
                .json({

                    message:
                        "Procurement added successfully.",

                    id:
                        result.id

                });

        }

        catch (error) {

            console.error(
                "Add procurement error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to add procurement to Salesforce."

                });

        }

    }
);


// =========================================================
// UPDATE PROCUREMENT
// =========================================================

app.put(
    "/api/procurements/:id",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const procurementId =
                req.params.id;


            const {
                procurementDate,
                grossWeight,
                bagDeduction,
                paddyRate
            } = req.body;


            // Farmer__c is intentionally not updated here.
            //
            // This preserves the working Salesforce configuration
            // established earlier.


            // Validate Salesforce ID.

            if (
                !isValidSalesforceId(procurementId)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Invalid Salesforce procurement ID."

                    });

            }


            // Validate date.

            if (
                typeof procurementDate !== "string" ||
                procurementDate.trim() === ""
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Procurement date is required."

                    });

            }


            // Validate gross weight.

            if (
                !isPositiveNumber(grossWeight)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Gross weight must be greater than 0."

                    });

            }


            // Validate bag deduction.

            if (
                !isNonNegativeNumber(bagDeduction)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Bag deduction cannot be negative."

                    });

            }


            // Validate paddy rate.

            if (
                !isPositiveNumber(paddyRate)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Paddy rate must be greater than 0."

                    });

            }


            // Update Salesforce record.

            const result =
                await salesforceConnection
                    .sobject(
                        "Paddy_Procurement__c"
                    )
                    .update({

                        Id:
                            procurementId,

                        Procurement_Date__c:
                            procurementDate,

                        Gross_Weight__c:
                            Number(grossWeight),

                        Bag_Deduction__c:
                            Number(bagDeduction),

                        Paddy_Rate__c:
                            Number(paddyRate)

                    });


            console.log(
                "Procurement updated:",
                result
            );


            if (!result.success) {

                return res
                    .status(500)
                    .json({

                        error:
                            "Failed to update procurement in Salesforce."

                    });

            }


            res.json({

                message:
                    "Procurement updated successfully.",

                id:
                    procurementId

            });

        }

        catch (error) {

            console.error(
                "Update procurement error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to update procurement in Salesforce."

                });

        }

    }
);


// =========================================================
// DELETE PROCUREMENT
// =========================================================

app.delete(
    "/api/procurements/:id",
    requireSalesforceConnection,
    async (req, res) => {

        try {

            const procurementId =
                req.params.id;


            if (
                !isValidSalesforceId(procurementId)
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Invalid Salesforce procurement ID."

                    });

            }


            const result =
                await salesforceConnection
                    .sobject(
                        "Paddy_Procurement__c"
                    )
                    .delete(
                        procurementId
                    );


            console.log(
                "Procurement deleted:",
                result
            );


            if (!result.success) {

                return res
                    .status(500)
                    .json({

                        error:
                            "Failed to delete procurement from Salesforce."

                });

            }


            res.json({

                message:
                    "Procurement deleted successfully.",

                id:
                    procurementId

            });

        }

        catch (error) {

            console.error(
                "Delete procurement error:",
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Failed to delete procurement from Salesforce."

                });

        }

    }
);


// =========================================================
// GLOBAL ERROR HANDLER
// =========================================================

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled application error:",
            error
        );


        if (
            error.message &&
            error.message.startsWith("CORS policy")
        ) {

            return res
                .status(403)
                .json({

                    error:
                        "Request blocked by CORS policy."

                });

        }


        res
            .status(500)
            .json({

                error:
                    "Internal server error."

            });

    }
);


// =========================================================
// START SERVER
// =========================================================

const PORT =
    process.env.PORT || 3000;


app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Backend running on port ${PORT}`
        );

    }
);