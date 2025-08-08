require('dotenv').config(); // Load environment variables from .env file
const express = require('express'); // Import Express framework
const cors = require('cors'); // Import CORS middleware to handle cross-origin requests
const { MongoClient, ServerApiVersion } = require('mongodb'); // Import MongoDB client and server API version
const { ObjectId } = require('mongodb'); // Import ObjectId to work with MongoDB document IDs
const admin = require("firebase-admin");

const decoded = Buffer.from(process.env.FIREBASE_ADMIN_SERVICE_KEY, 'base64').toString('utf8');

// Initialize Firebase Admin SDK
try {
    const serviceAccount = JSON.parse(decoded);

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });

    console.log("Firebase admin initialized");
} catch (error) {
    console.error("Failed to parse service account key:", error);
}


// Initialize Express application
const app = express();
const port = process.env.PORT || 3000; // Use port from environment or fallback to 3000

// Middleware setup
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Enable JSON body parsing for incoming requests

// Root route - simple health check endpoint
app.get('/', (req, res) => {
    res.send('Wow !!! ReadRack Server is Successfully running');
});

// MongoDB client initialization with server API options for stable behavior
const client = new MongoClient(process.env.DB_URI, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});




// Production-ready middleware with minimal logging
const verifyFirebaseToken = async (req, res, next) => {

    const authHeader = req.headers?.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ error: true, message: 'Unauthorized access' });
    }

    const idToken = authHeader.split(' ')[1];

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);

        // If email is missing from token, fetch it from Firebase User Record
        if (!decodedToken.email) {
            const userRecord = await admin.auth().getUser(decodedToken.uid);
            // Set email from user record

            if (userRecord.email) {
                decodedToken.email = userRecord.email;
            } else {
                // If still no email, check providerData
                const googleProvider = userRecord.providerData?.find(
                    provider => provider.providerId === 'google.com'
                );

                if (googleProvider?.email) {
                    decodedToken.email = googleProvider.email;
                } else {
                    return res.status(400).send({
                        error: true,
                        message: 'No email associated with this account'
                    });
                }
            }
        }

        req.user = decodedToken;
        next();
    } catch (error) {
        console.error('Error verifying Firebase ID token:', error);
        res.status(401).send({ error: true, message: 'Unauthorized access' });
    }
};

// Middleware to verify the email in the query parameter (only when email is provided)
const verifyTokenEmail = (req, res, next) => {
    const email = req.query.email;


    if (!email) {
        return next();
    }

    if (!req.user || !req.user.email) {
        return res.status(401).send({
            error: true,
            message: 'Unauthorized - User information missing'
        });
    }

    if (req.user.email !== email) {
        return res.status(403).send({
            error: true,
            message: 'Forbidden access - can only access your own books'
        });
    }

    next();
};



// Main async function to run server logic after connecting to DB
async function run() {
    try {
        // await client.connect(); // Connect to MongoDB

        // Reference collections from database
        const userCollection = client.db("readRackDB").collection("users");
        const bookCollection = client.db("readRackDB").collection("books");
        const reviewCollection = client.db("readRackDB").collection("reviews");








        // ********* Book related APIs *********

        // GET /books/my-books - Fetch books for the authenticated user (no search or filter)
        app.get('/books/my-books', verifyFirebaseToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                if (!userEmail) {
                    return res.status(400).json({ message: 'User email not found in token' });
                }

                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 20;
                const skip = (page - 1) * limit;

                // Query only by user email
                const query = { user_email: userEmail };

                // Count total books for user
                const totalBooks = await bookCollection.countDocuments(query);

                // Fetch paginated books for user, sorted newest first
                const books = await bookCollection.find(query)
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.status(200).json({
                    books,
                    totalBooks,
                    totalPages: Math.ceil(totalBooks / limit),
                    currentPage: page,
                    message: totalBooks === 0 ? 'No books found in your collection' : undefined
                });

            } catch (err) {
                console.error('Error fetching user books:', err);
                res.status(500).json({ message: 'Failed to fetch your books' });
            }
        });

        // GET /books/my-books/stats - Get user's reading statistics
        app.get('/books/my-books/stats', verifyFirebaseToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                if (!userEmail) {
                    return res.status(400).json({ message: 'User email not found in token' });
                }

                // Aggregate user's reading statistics
                const stats = await bookCollection.aggregate([
                    { $match: { user_email: userEmail } },
                    {
                        $group: {
                            _id: '$reading_status',
                            count: { $sum: 1 }
                        }
                    },
                    {
                        $group: {
                            _id: null,
                            total: { $sum: '$count' },
                            statusBreakdown: {
                                $push: {
                                    status: '$_id',
                                    count: '$count'
                                }
                            }
                        }
                    },
                    {
                        $project: {
                            _id: 0,
                            total: 1,
                            statusBreakdown: 1
                        }
                    }
                ]).toArray();

                const result = stats[0] || { total: 0, statusBreakdown: [] };

                res.status(200).json(result);

            } catch (err) {
                console.error('Error fetching user stats:', err);
                res.status(500).json({ message: 'Failed to fetch reading statistics' });
            }
        });

        // Modified GET /books route - authentication is optional for public access
        app.get('/books', async (req, res) => {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const skip = (page - 1) * limit;

            const search = req.query.search || '';
            const readingStatus = req.query.status || '';

            // Build MongoDB query
            let query = {};
            if (search) {
                query.$or = [
                    { book_title: { $regex: search, $options: 'i' } },
                    { book_author: { $regex: search, $options: 'i' } }
                ];
            }
            if (readingStatus) {
                query.reading_status = readingStatus;
            }

            try {
                const totalBooks = await bookCollection.countDocuments(query);
                const books = await bookCollection.find(query)
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.status(200).json({
                    books,
                    totalBooks,
                    totalPages: Math.ceil(totalBooks / limit),
                    currentPage: page
                });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to fetch books' });
            }
        });

        // GET /books/popular - Fetch popular books
        app.get('/books/popular', async (req, res) => {
            try {
                // Fetch all books that have an integer upvote value
                const popularBooks = await bookCollection.find({
                    upvote: { $type: "int" }  // Mongo filter for integer type (optional, ensures numeric)
                })
                    .sort({ upvote: -1 })   // Sort descending by upvote count
                    .limit(8)               // Limit to top 8 popular books
                    .toArray();

                res.status(200).json(popularBooks);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to fetch popular books' });
            }
        });

        // GET /books/categories - Get distinct categories with book count and a sample cover
        app.get('/books/categories', async (req, res) => {
            try {
                const categories = await bookCollection.aggregate([
                    {
                        $group: {
                            _id: '$book_category',
                            count: { $sum: 1 },
                            sampleCover: { $first: '$cover_photo' }
                        }
                    },
                    {
                        $project: {
                            category: '$_id',
                            count: 1,
                            sampleCover: 1,
                            _id: 0
                        }
                    }
                ]).toArray();
                res.status(200).json(categories);
            } catch (err) {
                console.error('Failed to fetch categories:', err);
                res.status(500).json({ message: 'Failed to fetch categories' });
            }
        });

        // GET /books/:id - Fetch a single book by its ID (handles both ObjectId and string IDs)
        app.get('/books/:id', verifyFirebaseToken, async (req, res) => {
            const id = req.params.id;

            try {
                // If id is a valid ObjectId, query by _id; else query by string ID
                const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { _id: id };
                const book = await bookCollection.findOne(query);

                if (!book) {
                    return res.status(404).json({ message: 'Book not found' });
                }

                res.status(200).json(book);
            } catch (err) {
                console.error('❌ Error fetching book:', err);
                res.status(500).json({ message: 'Error fetching book' });
            }
        });

        // POST /books - Add a new book document
        app.post('/books', async (req, res) => {
            const {
                book_title,
                cover_photo,
                total_page,
                book_author,
                user_email,
                user_name,
                book_category,
                reading_status,
                book_overview
            } = req.body;

            // Define valid categories and statuses
            const validCategories = [
                "Fiction",
                "Historical Fiction",
                "Romance",
                "Fantasy",
                "Non-Fiction",
                "Thriller",
                "Science Fiction",
                "Mystery"
            ];

            const validStatuses = ["Read", "Reading", "Want-to-Read"];

            // Basic required fields check
            if (
                !book_title || !cover_photo || !total_page || !book_author ||
                !user_email || !user_name || !book_category || !reading_status
            ) {
                return res.status(400).json({ message: 'Missing required fields' });
            }

            // Validate total_page
            const pages = Number(total_page);
            if (isNaN(pages) || pages <= 0) {
                return res.status(400).json({ message: 'Total pages must be a positive number' });
            }

            // Validate category and status
            if (!validCategories.includes(book_category)) {
                return res.status(400).json({ message: 'Invalid book category' });
            }

            if (!validStatuses.includes(reading_status)) {
                return res.status(400).json({ message: 'Invalid reading status' });
            }

            // Construct the book object
            const newBook = {
                book_title: book_title.trim(),
                cover_photo: cover_photo.trim(),
                total_page: pages,
                book_author: book_author.trim(),
                user_email: user_email.trim(),
                user_name: user_name.trim(),
                book_category,
                reading_status,
                book_overview: (book_overview || '').trim(),
                upvote: 0
            };

            try {
                const result = await bookCollection.insertOne(newBook);
                res.status(201).json({
                    message: 'Book added successfully',
                    bookId: result.insertedId
                });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to add book' });
            }
        });

        // PUT /books/:id - Update an existing book by its ID
        app.put('/books/:id', async (req, res) => {
            const { id } = req.params;

            // Check if ID is valid
            if (!ObjectId.isValid(id)) {
                return res.status(400).json({ message: "Invalid book ID" });
            }

            // Clone and clean the input
            const updatedData = { ...req.body };
            delete updatedData._id; // Prevent overwriting the _id field

            // Optional: Sanitize numeric fields
            if (updatedData.total_page) {
                updatedData.total_page = Number(updatedData.total_page);
                if (isNaN(updatedData.total_page) || updatedData.total_page <= 0) {
                    return res.status(400).json({ message: "Invalid total_page value" });
                }
            }

            try {
                const result = await bookCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updatedData }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: "Book not found" });
                }

                if (result.modifiedCount === 0) {
                    return res.status(200).json({ message: "No changes made, but book exists" });
                }

                res.status(200).json({ message: "Book updated successfully" });
            } catch (err) {
                console.error("Error updating book:", err);
                res.status(500).json({ message: "Failed to update book" });
            }
        });

        // DELETE /books/:id - Delete a book by its ID
        app.delete('/books/:id', async (req, res) => {
            const id = req.params.id;
            const result = await bookCollection.deleteOne({ _id: new ObjectId(id) });
            if (result.deletedCount === 1) {
                res.json({ message: "Deleted" });
            } else {
                res.status(404).json({ message: "Book not found" });
            }
        });

        // PUT /books/upvote/:id - Increment the upvote count for a book
        app.put('/books/upvote/:id', async (req, res) => {
            const bookId = req.params.id;
            const { email } = req.body;

            if (!email) {
                return res.status(400).json({ message: 'User email is required' });
            }

            try {
                // Find book to check existence and ownership
                const book = await bookCollection.findOne({ _id: new ObjectId(bookId) });

                if (!book) {
                    return res.status(404).json({ message: 'Book not found' });
                }

                // Prevent users from upvoting their own books
                if (book.user_email === email) {
                    return res.status(400).json({ message: 'You cannot upvote your own book' });
                }

                // Increment upvote count by 1
                const updatedBook = await bookCollection.updateOne(
                    { _id: new ObjectId(bookId) },
                    { $inc: { upvote: 1 } }
                );

                if (updatedBook.modifiedCount === 0) {
                    return res.status(400).json({ message: 'Failed to upvote the book' });
                }

                res.status(200).json({ message: 'Book upvoted successfully' });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to upvote the book' });
            }
        });

        // PUT /books/:bookId/status - Update the reading status of a book
        app.put('/books/:bookId/status', async (req, res) => {
            const { bookId } = req.params;
            const { email, newStatus } = req.body;

            if (!email || !newStatus) {
                return res.status(400).json({ message: 'Email and new status are required' });
            }

            try {
                // Find the book to verify ownership and status
                const book = await bookCollection.findOne({ _id: new ObjectId(bookId) });

                if (!book) {
                    return res.status(404).json({ message: 'Book not found' });
                }

                // Check if the book belongs to the user making the request
                if (book.user_email !== email) {
                    return res.status(403).json({ message: 'You can only update the status of your own book' });
                }

                // Valid statuses for reading status
                const validStatuses = ['Want-to-Read', 'Reading', 'Read'];
                if (!validStatuses.includes(newStatus)) {
                    return res.status(400).json({ message: 'Invalid reading status' });
                }

                // Valid status transitions (e.g., Want-to-Read -> Reading -> Read)
                const validTransitions = {
                    'Want-to-Read': 'Reading',
                    'Reading': 'Read',
                };

                // Ensure current status is valid and transition is allowed
                if (book.reading_status !== 'Want-to-Read' && book.reading_status !== 'Reading') {
                    return res.status(400).json({ message: 'Invalid status transition' });
                }

                if (validTransitions[book.reading_status] !== newStatus) {
                    return res.status(400).json({ message: 'Invalid transition of reading status' });
                }

                // Update the book's reading status
                const updatedBook = await bookCollection.updateOne(
                    { _id: new ObjectId(bookId) },
                    { $set: { reading_status: newStatus } }
                );

                if (updatedBook.modifiedCount === 0) {
                    return res.status(400).json({ message: 'Failed to update reading status' });
                }

                res.status(200).json({ message: 'Reading status updated successfully' });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to update reading status' });
            }
        });








        // ********* User related APIs *********

        // GET /users/:email - Fetch user info by email
        app.get('/users/:email', async (req, res) => {
            try {
                const email = decodeURIComponent(req.params.email);
                const user = await userCollection.findOne({ email });

                if (!user) {
                    return res.status(404).json({ message: 'User not found' });
                }

                res.status(200).json(user);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to fetch user' });
            }
        });

        // POST /users - Create a new user
        app.post('/users', async (req, res) => {
            try {
                const { name, email, profile_photo } = req.body;

                if (!name || !email) {
                    return res.status(400).json({ message: 'Name and email are required.' });
                }

                const existingUser = await userCollection.findOne({ email });
                if (existingUser) {
                    return res.status(409).json({ message: 'User already exists.' });
                }

                const user = { name, email, profile_photo: profile_photo || null };
                const result = await userCollection.insertOne(user);

                // Return the created user (with insertedId)
                res.status(201).json({
                    message: 'User created successfully',
                    user: { _id: result.insertedId, ...user }
                });
            } catch (err) {
                console.error('Failed to create user:', err);
                res.status(500).json({ message: 'Internal server error' });
            }
        });

        // PATCH /users/:email - Update user profile info (name, photo) with upsert
        app.patch('/users/:email', async (req, res) => {
            try {
                const email = decodeURIComponent(req.params.email);
                const { name, profile_photo } = req.body;

                if (!name && !profile_photo) {
                    return res.status(400).json({ message: 'At least one field (name or profile photo) is required.' });
                }

                const updateFields = {};
                if (name) updateFields.name = name;
                if (profile_photo !== undefined) updateFields.profile_photo = profile_photo;

                // Upsert: create user if not exists
                const result = await userCollection.updateOne(
                    { email },
                    { $set: updateFields, $setOnInsert: { email } },
                    { upsert: true }
                );

                if (result.upsertedCount > 0) {
                    return res.status(201).json({ message: 'User not found. New user created.', email });
                }

                if (result.matchedCount === 0) {
                    // This should not happen with upsert:true, but just in case:
                    return res.status(404).json({ message: 'User not found.' });
                }

                if (result.modifiedCount === 0) {
                    return res.status(200).json({ message: 'User found but no changes made (fields are same).' });
                }

                res.status(200).json({ message: 'User updated successfully' });
            } catch (err) {
                console.error('Failed to update user:', err);
                res.status(500).json({ message: 'Internal server error' });
            }
        });







        // ********* Review related APIs *********

        // GET /reviews/:bookId - Get all reviews for a given book
        app.get('/reviews/:bookId', verifyFirebaseToken, async (req, res) => {
            const bookId = req.params.bookId;
            try {
                const reviews = await reviewCollection.find({ book_id: new ObjectId(bookId) }).toArray();
                res.status(200).json(reviews);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to fetch reviews' });
            }
        });

        // POST /reviews - Add a new review for a book
        app.post('/reviews', async (req, res) => {
            const { book_id, user_email, review_text } = req.body;

            // Check if the user has already reviewed the book
            const existingReview = await reviewCollection.findOne({ book_id: new ObjectId(book_id), user_email });
            if (existingReview) {
                return res.status(400).json({ message: 'You have already posted a review for this book.' });
            }

            // Insert new review with timestamp
            const newReview = { book_id: new ObjectId(book_id), user_email, review_text, created_at: new Date() };
            const result = await reviewCollection.insertOne(newReview);
            res.status(201).json(result);
        });

        // PUT /reviews/:reviewId - Update an existing review
        app.put('/reviews/:reviewId', async (req, res) => {
            const reviewId = req.params.reviewId;
            const { user_email, review_text } = req.body;

            if (!review_text || !user_email) {
                return res.status(400).json({ message: 'Missing required fields' });
            }

            try {
                const review = await reviewCollection.findOne({ _id: new ObjectId(reviewId) });

                if (!review) {
                    return res.status(404).json({ message: 'Review not found' });
                }

                // Ensure user owns the review before allowing update
                if (review.user_email !== user_email) {
                    return res.status(403).json({ message: 'You can only update your own review' });
                }

                const result = await reviewCollection.updateOne(
                    { _id: new ObjectId(reviewId) },
                    { $set: { review_text } }
                );

                if (result.modifiedCount === 0) {
                    return res.status(404).json({ message: 'No changes made' });
                }

                res.status(200).json({ message: 'Review updated successfully' });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to update review' });
            }
        });

        // DELETE /reviews/:reviewId - Delete a review
        app.delete('/reviews/:reviewId', async (req, res) => {
            const reviewId = req.params.reviewId;
            const { user_email } = req.body;

            if (!user_email) {
                return res.status(400).json({ message: 'User email is required' });
            }

            try {
                const review = await reviewCollection.findOne({ _id: new ObjectId(reviewId) });

                if (!review) {
                    return res.status(404).json({ message: 'Review not found' });
                }

                // Ensure user owns the review before allowing deletion
                if (review.user_email !== user_email) {
                    return res.status(403).json({ message: 'You can only delete your own review' });
                }

                const result = await reviewCollection.deleteOne({ _id: new ObjectId(reviewId) });

                if (result.deletedCount === 0) {
                    return res.status(404).json({ message: 'Failed to delete review' });
                }

                res.status(200).json({ message: 'Review deleted successfully' });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to delete review' });
            }
        });









        // Ping the DB to verify connection is alive
        // await client.db("admin").command({ ping: 1 });
        console.log("✅ Connected to MongoDB!");
    } catch (err) {
        console.error('❌ MongoDB connection error:', err);
    }
}

// Run the async server setup function
run().catch(console.dir);

// Start Express server and listen on the configured port
app.listen(port, () => {
    console.log(`🚀 Server listening on port ${port}`);
});