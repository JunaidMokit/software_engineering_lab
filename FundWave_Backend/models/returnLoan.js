
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs-extra');
const { check, validationResult } = require('express-validator');
const dayjs = require('dayjs');

// --------------------
// CONFIG
// --------------------
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_secure_secret';
const DATA_DIR = './data';
const USERS_FILE = `${DATA_DIR}/users.json`;
const LOANS_FILE = `${DATA_DIR}/loans.json`;
const PAYMENTS_FILE = `${DATA_DIR}/payments.json`;

// Ensure data directory exists
fs.ensureDirSync(DATA_DIR);

// Initialize files if missing
if (!fs.existsSync(USERS_FILE)) fs.writeJsonSync(USERS_FILE, []);
if (!fs.existsSync(LOANS_FILE)) fs.writeJsonSync(LOANS_FILE, []);
if (!fs.existsSync(PAYMENTS_FILE)) fs.writeJsonSync(PAYMENTS_FILE, []);

// Helper to read/write JSON
const readData = (file) => {
    try {
        return fs.readJsonSync(file);
    } catch (err) {
        console.error('readData error', err);
        return [];
    }
};

const writeData = (file, data) => {
    try {
        fs.writeJsonSync(file, data, { spaces: 2 });
    } catch (err) {
        console.error('writeData error', err);
    }
};

// --------------------
// SIMPLE MODELS (JSON-backed)
// --------------------
const Users = {
    all() { return readData(USERS_FILE); },
    findById(id) { return this.all().find(u => u.id === id); },
    findByEmail(email) { return this.all().find(u => u.email.toLowerCase() === email.toLowerCase()); },
    save(user) {
        const list = this.all();
        list.push(user);
        writeData(USERS_FILE, list);
        return user;
    },
    update(id, patch) {
        const list = this.all();
        const idx = list.findIndex(u => u.id === id);
        if (idx === -1) return null;
        list[idx] = { ...list[idx], ...patch };
        writeData(USERS_FILE, list);
        return list[idx];
    }
};

const Loans = {
    all() { return readData(LOANS_FILE); },
    findById(id) { return this.all().find(l => l.id === id); },
    save(loan) {
        const list = this.all();
        list.push(loan);
        writeData(LOANS_FILE, list);
        return loan;
    },
    update(id, patch) {
        const list = this.all();
        const idx = list.findIndex(l => l.id === id);
        if (idx === -1) return null;
        list[idx] = { ...list[idx], ...patch };
        writeData(LOANS_FILE, list);
        return list[idx];
    },
    filter(predicate) { return this.all().filter(predicate); }
};

const Payments = {
    all() { return readData(PAYMENTS_FILE); },
    findById(id) { return this.all().find(p => p.id === id); },
    save(payment) {
        const list = this.all();
        list.push(payment);
        writeData(PAYMENTS_FILE, list);
        return payment;
    },
    listForLoan(loanId) { return this.all().filter(p => p.loanId === loanId).sort((a, b) => new Date(a.date) - new Date(b.date)); }
};

// --------------------
// UTILITIES
// --------------------
async function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, hash) {
    return bcrypt.compare(password, hash);
}

function signToken(user) {
    const payload = { id: user.id, email: user.email, role: user.role };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return null;
    }
}

function requireAuth(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
    const token = auth.split(' ')[1];
    const payload = verifyToken(token);
    if (!payload) return res.status(401).json({ error: 'Invalid token' });
    req.user = payload;
    next();
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
        if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
        next();
    };
}

// Generate amortized schedule
function generateAmortizedSchedule(principal, annualRatePercent, months, startDate) {
    // monthly interest rate
    const r = annualRatePercent / 100 / 12;
    const n = months;
    let payment = 0;
    if (r === 0) payment = principal / n;
    else payment = principal * r / (1 - Math.pow(1 + r, -n));
    payment = Number(payment.toFixed(2));

    const schedule = [];
    let balance = principal;
    let date = dayjs(startDate);
    for (let i = 1; i <= n; i++) {
        const interest = Number((balance * r).toFixed(2));
        const principalPaid = Number((payment - interest).toFixed(2));
        balance = Number((balance - principalPaid).toFixed(2));
        if (i === n && balance !== 0) {
            // adjust last payment to clean rounding
            principalPaid += balance;
            payment = Number((principalPaid + interest).toFixed(2));
            balance = 0;
        }
        schedule.push({
            installmentNumber: i,
            dueDate: date.add(i - 1, 'month').format('YYYY-MM-DD'),
            paymentAmount: payment,
            principalComponent: principalPaid,
            interestComponent: interest,
            remainingBalance: balance
        });
    }
    return schedule;
}

// --------------------
// SEED ADMIN USER (if none exists)
// --------------------
(function seedAdmin() {
    const existing = Users.findByEmail('admin@loanapp.local');
    if (!existing) {
        (async () => {
            const passwordHash = await hashPassword('admin123');
            Users.save({
                id: uuidv4(),
                name: 'Admin',
                email: 'admin@loanapp.local',
                passwordHash,
                role: 'admin',
                createdAt: new Date().toISOString()
            });
            console.log('Seeded admin user: admin@loanapp.local / admin123');
        })();
    }
})();

// --------------------
// EXPRESS APP
// --------------------
const app = express();
app.use(bodyParser.json());

// --------------------
// ROUTES: AUTH
// --------------------

app.post('/api/auth/register', [
    check('name').isLength({ min: 2 }),
    check('email').isEmail(),
    check('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, password, role } = req.body;
    if (Users.findByEmail(email)) return res.status(400).json({ error: 'Email already registered' });
    const passwordHash = await hashPassword(password);
    const user = {
        id: uuidv4(),
        name,
        email,
        passwordHash,
        role: role || 'customer',
        createdAt: new Date().toISOString()
    };
    Users.save(user);
    const token = signToken(user);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/auth/login', [
    check('email').isEmail(),
    check('password').exists()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body;
    const user = Users.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await comparePassword(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = signToken(user);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// --------------------
// ROUTES: USERS (admin only)
// --------------------
app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
    const list = Users.all().map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, createdAt: u.createdAt }));
    res.json(list);
});

app.get('/api/users/me', requireAuth, (req, res) => {
    const user = Users.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ id: user.id, name: user.name, email: user.email, role: user.role, createdAt: user.createdAt });
});

// --------------------
// ROUTES: LOANS
// --------------------

/* Loan lifecycle statuses:
 - applied: customer applied, waiting approval
 - approved: officer/admin approved
 - disbursed: funds disbursed to customer
 - closed: balance 0
 - rejected: application rejected
*/

app.post('/api/loans/apply', requireAuth, requireRole('customer'), [
    check('amount').isFloat({ gt: 0 }),
    check('termMonths').isInt({ gt: 0 }),
    check('annualInterest').isFloat({ min: 0 }),
    check('purpose').isLength({ min: 3 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { amount, termMonths, annualInterest, purpose } = req.body;
    const principal = Number(amount);
    const months = Number(termMonths);
    const interest = Number(annualInterest);
    const startDate = dayjs().format('YYYY-MM-DD');

    const schedule = generateAmortizedSchedule(principal, interest, months, startDate);

    const loan = {
        id: uuidv4(),
        applicantId: req.user.id,
        amount: principal,
        termMonths: months,
        annualInterest: interest,
        purpose,
        status: 'applied',
        appliedAt: new Date().toISOString(),
        schedule,
        outstandingBalance: principal,
        approvedBy: null,
        approvedAt: null,
        disbursedAt: null,
        createdAt: new Date().toISOString()
    };

    Loans.save(loan);
    res.status(201).json(loan);
});

app.get('/api/loans', requireAuth, (req, res) => {
    const user = req.user;
    let list = Loans.all();
    if (user.role === 'customer') {
        list = list.filter(l => l.applicantId === user.id);
    }
    // optional query filters
    const { status, applicantId } = req.query;
    if (status) list = list.filter(l => l.status === status);
    if (applicantId) list = list.filter(l => l.applicantId === applicantId);
    res.json(list);
});

app.get('/api/loans/:id', requireAuth, (req, res) => {
    const loan = Loans.findById(req.params.id);
    if (!loan) return res.status(404).json({ error: 'Not found' });
    if (req.user.role === 'customer' && loan.applicantId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    res.json(loan);
});

// Approve loan: officer or admin
app.post('/api/loans/:id/approve', requireAuth, requireRole('admin', 'officer'), [
    check('approve').isBoolean()
], (req, res) => {
    const loan = Loans.findById(req.params.id);
    if (!loan) return res.status(404).json({ error: 'Not found' });
    if (loan.status !== 'applied') return res.status(400).json({ error: 'Loan must be in applied status' });
    const { approve, comment } = req.body;
    if (approve) {
        loan.status = 'approved';
        loan.approvedBy = req.user.id;
        loan.approvedAt = new Date().toISOString();
        loan.approvalComment = comment || null;
        Loans.update(loan.id, loan);
        return res.json(loan);
    } else {
        loan.status = 'rejected';
        loan.approvedBy = req.user.id;
        loan.approvedAt = new Date().toISOString();
        loan.approvalComment = comment || null;
        Loans.update(loan.id, loan);
        return res.json(loan);
    }
});

// Disburse loan funds: admin/officer
app.post('/api/loans/:id/disburse', requireAuth, requireRole('admin', 'officer'), (req, res) => {
    const loan = Loans.findById(req.params.id);
    if (!loan) return res.status(404).json({ error: 'Not found' });
    if (loan.status !== 'approved') return res.status(400).json({ error: 'Loan must be approved before disbursement' });
    loan.status = 'disbursed';
    loan.disbursedAt = new Date().toISOString();
    loan.outstandingBalance = loan.amount; // principal
    Loans.update(loan.id, loan);
    res.json(loan);
});

// Record a payment: customer or teller
app.post('/api/loans/:id/pay', requireAuth, [
    check('amount').isFloat({ gt: 0 })
], (req, res) => {
    const loan = Loans.findById(req.params.id);
    if (!loan) return res.status(404).json({ error: 'Not found' });
    if (req.user.role === 'customer' && loan.applicantId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    if (loan.status !== 'disbursed') return res.status(400).json({ error: 'Loan not disbursed' });

    const { amount, note, date } = req.body;
    const paymentAmount = Number(amount);
    const paymentDate = date || new Date().toISOString();

    const payment = {
        id: uuidv4(),
        loanId: loan.id,
        payerId: req.user.id,
        amount: paymentAmount,
        date: paymentDate,
        note: note || null,
        createdAt: new Date().toISOString()
    };

    Payments.save(payment);

    // Apply payment to schedule: simple approach - reduce outstanding balance
    loan.outstandingBalance = Number((loan.outstandingBalance - paymentAmount).toFixed(2));
    if (loan.outstandingBalance <= 0) {
        loan.outstandingBalance = 0;
        loan.status = 'closed';
        loan.closedAt = new Date().toISOString();
    }

    Loans.update(loan.id, loan);

    res.json({ payment, loan });
});

// Get payments for a loan
app.get('/api/loans/:id/payments', requireAuth, (req, res) => {
    const loan = Loans.findById(req.params.id);
    if (!loan) return res.status(404).json({ error: 'Not found' });
    if (req.user.role === 'customer' && loan.applicantId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    const payments = Payments.listForLoan(loan.id);
    res.json(payments);
});

// --------------------
// REPORTS & ADMIN ENDPOINTS
// --------------------

app.get('/api/reports/portfolio', requireAuth, requireRole('admin', 'officer'), (req, res) => {
    const loans = Loans.all();
    const totalLoans = loans.length;
    const totalOutstanding = loans.reduce((s, l) => s + (l.outstandingBalance || 0), 0);
    const disbursed = loans.filter(l => l.status === 'disbursed').length;
    const closed = loans.filter(l => l.status === 'closed').length;
    const applied = loans.filter(l => l.status === 'applied').length;
    const approved = loans.filter(l => l.status === 'approved').length;
    res.json({ totalLoans, totalOutstanding, disbursed, closed, applied, approved });
});

app.get('/api/reports/delinquent', requireAuth, requireRole('admin', 'officer'), (req, res) => {
    const loans = Loans.all().filter(l => l.status === 'disbursed');
    const today = dayjs();
    const delinquent = loans.filter(l => {
        // a loan is delinquent if any scheduled dueDate is before today and remainingBalance > 0
        return l.schedule.some(s => dayjs(s.dueDate).isBefore(today) && s.remainingBalance > 0) && l.outstandingBalance > 0;
    }).map(l => ({ id: l.id, applicantId: l.applicantId, outstandingBalance: l.outstandingBalance }));
    res.json(delinquent);
});

// Search loans by various fields
app.get('/api/search/loans', requireAuth, (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ error: 'q query param is required' });
    const loans = Loans.all();
    const out = loans.filter(l => {
        return String(l.id).includes(q) || String(l.applicantId).includes(q) || (l.purpose || '').toLowerCase().includes(q.toLowerCase());
    });
    res.json(out);
});

// --------------------
// MAINTENANCE: Recalculate schedule balances based on payments
// --------------------
app.post('/api/admin/recalculate/:loanId', requireAuth, requireRole('admin', 'officer'), (req, res) => {
    const loan = Loans.findById(req.params.loanId);
    if (!loan) return res.status(404).json({ error: 'Not found' });
    const payments = Payments.listForLoan(loan.id);
    let balance = loan.amount;
    const schedule = generateAmortizedSchedule(loan.amount, loan.annualInterest, loan.termMonths, loan.appliedAt);
    // Walk through payments and reduce schedule remaining balances in order
    payments.forEach(p => {
        let remaining = p.amount;
        for (let i = 0; i < schedule.length && remaining > 0; i++) {
            const installment = schedule[i];
            const dueRem = installment.remainingBalance;
            if (dueRem <= 0) continue;
            const apply = Math.min(remaining, installment.paymentAmount);
            installment.remainingBalance = Number((installment.remainingBalance - apply).toFixed(2));
            remaining = Number((remaining - apply).toFixed(2));
        }
    });
    // recompute outstanding balance as sum of last remainingBalance or directly reduce by payments
    const paid = payments.reduce((s, p) => s + p.amount, 0);
    loan.outstandingBalance = Number((loan.amount - paid).toFixed(2));
    if (loan.outstandingBalance <= 0) {
        loan.status = 'closed';
        loan.closedAt = new Date().toISOString();
        loan.outstandingBalance = 0;
    }
    loan.schedule = schedule;
    Loans.update(loan.id, loan);
    res.json(loan);
});

// --------------------
// ADMIN: create officer
// --------------------
app.post('/api/admin/create-officer', requireAuth, requireRole('admin'), [
    check('name').isLength({ min: 2 }),
    check('email').isEmail(),
    check('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name, email, password } = req.body;
    if (Users.findByEmail(email)) return res.status(400).json({ error: 'Email exists' });
    const passwordHash = await hashPassword(password);
    const user = { id: uuidv4(), name, email, passwordHash, role: 'officer', createdAt: new Date().toISOString() };
    Users.save(user);
    res.json({ id: user.id, name: user.name, email: user.email });
});

// --------------------
// HEALTH & DEBUG
// --------------------
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/debug/dump', requireAuth, requireRole('admin'), (req, res) => {
    res.json({ users: Users.all(), loans: Loans.all(), payments: Payments.all() });
});

// --------------------
// GLOBAL ERROR HANDLING
// --------------------
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// --------------------
// START SERVER
// --------------------
app.listen(PORT, () => {
    console.log(`Loan Management API listening on port ${PORT}`);
    console.log('Available endpoints:');
    console.log('POST /api/auth/register');
    console.log('POST /api/auth/login');
    console.log('POST /api/loans/apply');
    console.log('POST /api/loans/:id/pay');
});


