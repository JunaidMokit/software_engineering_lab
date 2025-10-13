import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Container, Button, Table, Text, Notification, Title, Loader, NumberInput } from '@mantine/core';
import { Link, useParams } from 'react-router-dom';
import { IconCurrencyTaka } from '@tabler/icons-react';
import EMIPayments from './Emipayments';
// LoanPayments Component
const LoanPayments = ({ loan, loanId,bids }) => {
  const [payments, setPayments] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [totalPaid, setTotalPaid] = useState(0);
  const [payvalue, setPayvalue] = useState(0);
  const username = localStorage.getItem('username'); 
  const [totaldebt, setTotaldebt] = useState(0);
    useEffect(() => {
    // Fetch loan payment details from the backend
    const fetchPayments = async () => {
      try {
        const response = await axios.get(`http://localhost:3000/api/loanpayments/${loanId}`);
        setPayments(response.data);
        
        // Calculate the total amount paid
        const total = response.data.reduce((acc, payment) => {
            if (payment.give === loan.username) {
              return acc + payment.Amount;
            }
            return acc;
          }, 0);

          const debt = response.data.reduce((acc, payment) => {
            if (payment.give !== loan.username) {
              return acc + payment.Amount;
            }
            return acc;
          }, 0);
          setTotaldebt(debt);
          setTotalPaid(total);
      } catch (error) {
        setError('Error fetching payment details.');
      } finally {
        setIsLoading(false);
      }
    };
  
    fetchPayments();
  }, [loanId]);

  const remainingDebt = totaldebt + totaldebt * (loan.interest / 100) - totalPaid + (bids.bonus ? bids.bonus : 0);

  const handlePayment = async () => {
    if (payvalue <= 0 || payvalue > remainingDebt) {
      setError('Please enter a valid amount to pay.');
      return;
    }
    try {
      setIsLoading(true);
      const { data } = await axios.post('http://localhost:3000/api/payment/givepay', {
        plan: "loan",
        price: payvalue,
        username: loan.username,
        id: loan._id,
      });

      if (data.url) {
        window.location.replace(data.url);
      } else {
        setError('Payment failed. Please try again.');
      }
    } catch (error) {
      setError('Payment failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Container>
      <Title order={2} mb="md">Loan Payments</Title>
      {payments.length > 0 ? (
        <Table highlightOnHover withBorder>
          <thead>
            <tr>
              <th>Transaction ID</th>
              <th>Amount</th>
              <th>Giver</th>
              <th>Status</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {payments.map((payment) => (
              <tr key={payment._id}>
                <td>{payment.trans}</td>
                <td>${payment.Amount.toFixed(2)}</td>
                <td>{payment.give}</td>
                <td>{payment.status}</td>
                <td>{new Date(payment.createdAt).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <Text>No payments found for this loan.</Text>
      )}

      <Title order={3} mt="lg">Loan Summary</Title>
      <Table highlightOnHover withBorder mt="md">
        <tbody>
          <tr>
            <td>Total Payable Amount</td>
            <td>৳{((bids.bonus ? bids.bonus : 0) + totaldebt + totaldebt * (loan.interest / 100.0)).toFixed(2)}</td>
          </tr>
          <tr>
            <td>Total Interest</td>
            <td>৳{(totaldebt * (loan.interest / 100)).toFixed(2)}</td>
          </tr>
          <tr>
            <td>Total Bonus</td>
            <td>৳{(bids.bonus ? bids.bonus : 0).toFixed(2)}</td>
          </tr>
          <tr>
            <td>Total Paid</td>
            <td>৳{totalPaid.toFixed(2)}</td>
          </tr>
          <tr>
            <td>Remaining Debt</td>
            <td>৳{remainingDebt.toFixed(2)}</td>
          </tr>
        </tbody>
      </Table>

      {remainingDebt > 0 && username === loan.username && (
        <>
          <NumberInput
            label="How much do you want to pay?"
            precision={2}
            rightSection={<IconCurrencyTaka size={20} />}
            value={payvalue}
            onChange={(value) => setPayvalue(value || 0)}
            mt="md"
          />
          {error && (
            <Notification color="red" title="Error" mt="md">
              {error}
            </Notification>
          )}
          <Button onClick={handlePayment} loading={isLoading} fullWidth mt="md">
            Pay Remaining Debt
          </Button>
        </>
      )}
    </Container>
  )
}

// Main Trans Component
const Trans = () => {
  const [loan, setLoan] = useState(null);
  const [error, setError] = useState(null);
  const [isFetchingLoan, setIsFetchingLoan] = useState(true);
  const { id } = useParams();
  const username = localStorage.getItem('username');
  const [bids, setBids] = useState([]);
  const [finalBids, setFinalBids] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const fetchBids = async () => {
      try {
        const response = await axios.get(`http://localhost:3000/api/bids/${id}`);
        setBids(response.data.data);
        for(let i=0;i<response.data.data.length;i++){
          if(response.data.data[i].final==true){
            setFinalBids(response.data.data[i]);
            break;
          }
        }
      } catch (error) {
        console.error('Error fetching bids:', error);
      }
    };

    fetchBids();
  }, [id]);

  useEffect(() => {
    const fetchLoan = async () => {
      try {
        const response = await axios.get(`http://localhost:3000/api/loans/${id}`);
        setLoan(response.data);
      } catch (error) {
        setError('Error fetching loan details.');
      } finally {
        setIsFetchingLoan(false);
      }
    };

    fetchLoan();
  }, [id]);

  const meFinal = finalBids.username === username;
  const isOwner = loan?.username === username;

  if (!isOwner && !meFinal) {
    return (
      <Container>
        <Text>Sorry, you are not allowed to access this page.</Text>
      </Container>
    );
  }

  const handlePayment = async () => {
    setIsLoading(true);
    try {
      const { data } = await axios.post('http://localhost:3000/api/payment/givepay', {
        plan: "loan",
        price: loan.targetAmount, // Assuming price is the target amount
        username: username,
        id: loan._id,
      });

      // Check if the URL is present in the response
      if (data.url) {
        // Redirect the user to the payment page
        window.location.replace(data.url);
      } else {
        setError('Payment failed. Please try again.');
      }
    } catch (error) {
      setError('Payment failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <Container>
      {isFetchingLoan ? (
        <Text>Loading loan details...</Text>
      ) : loan ? (
        <>
          <Title order={2}>Loan Details</Title>
          <Table highlightOnHover withBorder>
            <thead>
              <tr>
                <th>Title</th>
                <th>Loan</th>
                <th>Interest</th>
                <th>Deadline</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>{loan.title}</td>
                <td>৳{loan.targetAmount}</td>
                <td>{loan.interest}%</td>
                <td>{new Date(loan.deadlineDate).toLocaleDateString()}</td>
                <td>
                  <Link to={`/loans/${loan._id}`}>View Details</Link>
                </td>
              </tr>
            </tbody>
          </Table>

          {username !== loan.username && (
            <Button onClick={handlePayment} loading={isLoading} fullWidth mt="md">
              Proceed to Lend
            </Button>
          )}

          {error && (
            <Notification color="red" title="Error" mt="md">
              {error}
            </Notification>
          )}

          <LoanPayments loan={loan} loanId={loan._id} bids={finalBids} />
          {finalBids.type === 'EMI' && <EMIPayments loan={loan} bids={finalBids} />}
        </>
      ) : (
        <Text>No loan found</Text>
      )}
    </Container>
  );
};


export default Trans;