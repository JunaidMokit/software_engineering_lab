import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Container, Button, Table, Title } from '@mantine/core';
import { Link } from 'react-router-dom';

// EMI Payments Section
const EMIPayments = ({ loan, bids }) => {
  const [monthlyPayments, setMonthlyPayments] = useState([]);
  const [paidPayments, setPaidPayments] = useState([]);
  const [totalPaid, setTotalPaid] = useState(0);
  const [totalDebt, setTotalDebt] = useState(0);

  const monthsRemaining = calculateMonthDifference(bids.deadlineDate, bids.createdAt);
  
  useEffect(() => {
    const fetchPayments = async () => {
      try {
        const response = await axios.get(`http://localhost:3000/api/loanpayments/${loan._id}`);
        setPaidPayments(response.data);

        const total = response.data.reduce((acc, payment) => {
          return payment.give === loan.username ? acc + payment.Amount : acc;
        }, 0);

        const debt = response.data.reduce((acc, payment) => {
          return payment.give !== loan.username ? acc + payment.Amount : acc;
        }, 0);

        setTotalDebt(debt);
        setTotalPaid(total);
      } catch (error) {
        console.error('Error fetching paid payments:', error);
      }
    };
    fetchPayments();
  }, [loan._id]);

  useEffect(() => {
    const calculateEMIPayments = () => {
      const totalPayable =bids.bonus+ loan.targetAmount + (loan.targetAmount * loan.interest) / 100.00;
      const emiAmount = totalPayable*1.00 / monthsRemaining*1.00;
      const payments = Array.from({ length: monthsRemaining }, (_, i) => {
        const paymentMonth = new Date(bids.createdAt);
        paymentMonth.setMonth(paymentMonth.getMonth() + i + 1);
        return {
          month: paymentMonth.toLocaleString('default', { month: 'long', year: 'numeric' }), // e.g., "January 2023"
          amount: emiAmount.toFixed(2),
        };
      });
        setMonthlyPayments(payments);
    };

    calculateEMIPayments();
  }, [loan, monthsRemaining, bids.createdAt]);

  const username = localStorage.getItem('username');

  const hasPaidForMonth = (month) => {
    const totalPayable = loan.targetAmount + (loan.targetAmount * loan.interest) / 100;
    const emiAmount = totalPayable / monthsRemaining;
    const shouldPaid = emiAmount * (monthlyPayments.findIndex(p => p.month === month) + 1);

    if (totalDebt <= 0) {
      return true;
    }
    return totalPaid >= shouldPaid;
  };

  const monthPayment = (month) => {
    const totalPayable = loan.targetAmount + (loan.targetAmount * loan.interest) / 100;
    const emiAmount = totalPayable / monthsRemaining;
    const shouldPaid = emiAmount * (monthlyPayments.findIndex(p => p.month === month) + 1);
   

    if (totalDebt <= 0) {
      return 0;
    }

    if (totalPaid >= shouldPaid) {
      return emiAmount.toFixed(2);
    } else {
      return Math.min(emiAmount, shouldPaid - totalPaid).toFixed(2);
    }
  };

  const handlePayment = async (amount) => {
    try {
      const { data } = await axios.post('http://localhost:3000/api/payment/givepay', {
        plan: 'loan',
        price: amount,
        username: loan.username,
        id: loan._id,
      });

      if (data.url) {
        window.location.replace(data.url);
      } else {
        console.error('Payment failed. Please try again.');
      }
    } catch (error) {
      console.error('Payment failed. Please try again.', error);
    }
  };

  return (
    <Container>
      <Title order={3} mt="lg">EMI Payments</Title>
      <Table highlightOnHover withBorder mt="md">
        <thead>
          <tr>
            <th>Month</th>
            <th>Amount</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {monthlyPayments.length === 0 ? (
            <tr>
              <td colSpan="3">No payment schedule available.</td>
            </tr>
          ) : (
            monthlyPayments.map((payment, index) => (
              <tr key={index}>
                <td>{payment.month}</td>
                <td>${monthPayment(payment.month)}</td>
                <td>
                  {username !== loan.username ? (
                    <Link to={`/chat/${loan.username}`}>
                      <Button
                        variant="outline"
                        disabled={hasPaidForMonth(payment.month)}
                      >
                        {hasPaidForMonth(payment.month) ? 'Paid' : 'Message'}
                      </Button>
                    </Link>
                  ) : (
                    <Button
                      variant="outline"
                      onClick={() => handlePayment(monthPayment(payment.month))}
                      disabled={hasPaidForMonth(payment.month)}
                    >
                      {totalDebt <= 0 ? 'Not Applicable' : hasPaidForMonth(payment.month) ? 'Paid' : 'Pay Now'}
                    </Button>
                  )}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
    </Container>
  );
};

// Helper function to calculate month difference
const calculateMonthDifference = (deadlineDate, startDate) => {
  const deadline = new Date(deadlineDate);
  const start = new Date(startDate);
  return (
    deadline.getMonth() - start.getMonth() +
    12 * (deadline.getFullYear() - start.getFullYear())
  );
};

export default EMIPayments;
