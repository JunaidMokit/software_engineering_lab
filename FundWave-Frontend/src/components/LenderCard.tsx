import { useEffect, useState } from 'react';
import { Avatar, Button, Flex, Paper, Stack, Text, Progress, Modal, TextInput, NumberInput, Select, Input } from '@mantine/core';
import { IconSend } from '@tabler/icons-react';

interface IProps {
  lender: {
    username: string;
    _id: string;
    loanid: string;
    deadlineDate: string;
    interest: number;
    type: string;
    createdAt: string;
    final: boolean;
    // gap: string;
    bonus: Number;
  };
  final: boolean;
  own: boolean;
}

const LenderCard = ({ lender, final, own }: IProps) => {
  const [userInfo, setUserInfo] = useState<any>(null);
  const [review, setReview] = useState(9);
  const [isModalOpen, setIsModalOpen] = useState(false); // State for modal
  const [editableLender, setEditableLender] = useState({ ...lender }); // State for editable fields
  const [total, setTotal] = useState(0);

  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const response = await fetch(`http://localhost:3000/auth/user/${lender.username}`);
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        const data = await response.json();
        setUserInfo(data);
      } catch (error) {
        console.error('Error fetching user data:', error);
      }
    };

    fetchUserInfo();
  }, [lender.username]);

  const confirmlend = async () => {
    try {
      const response = await fetch(`http://localhost:3000/api/bids/${lender._id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...lender,
          final: true,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to submit bid');
      }
      // fetchLenderData();
      alert('Bid successfully submitted!');
    } catch (error) {
      console.error('Error submitting bid:', error);
    }
  };


  const updatebid = async () => {
    try {
      const response = await fetch(`http://localhost:3000/api/bids/${editableLender._id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(editableLender),
      });

      if (!response.ok) {
        throw new Error('Failed to update bid');
      }

      alert('Bid successfully updated!');
      setIsModalOpen(false); // Close modal on success
    } catch (error) {
      console.error('Error updating bid:', error);
    }
  };

  const fetchbids = async () => {
    try {
      const response = await fetch(`http://localhost:3000/api/bids/final/${editableLender.username}`);
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      setTotal(data.data.length);      
    } catch (error) {
      console.error('Error fetching bids:', error);
    }
  }
  useEffect(() => {
    fetchbids();
  }, [editableLender.loanid]);
  
  const username = localStorage.getItem('username');
  const handleClick = () => {
    setReview((prev) => (prev < 10 ? prev + 1 : 0));
  };

  if (!userInfo) {
    return <Text>Loading...</Text>;
  }
  const calculateMonthDifference = (deadlineDate: string) => {
    const currentDate = new Date();
    const deadline = new Date(deadlineDate);

    const yearDiff = deadline.getFullYear() - currentDate.getFullYear();
    const monthDiff = deadline.getMonth() - currentDate.getMonth();

    return yearDiff * 12 + monthDiff;
  };

  const monthsRemaining = calculateMonthDifference(editableLender.deadlineDate);


  const formatDate = (isoString: string) => {
    const date = new Date(isoString);
    return date.toISOString().split('T')[0]; // Extracts the YYYY-MM-DD part
  };
  

  
  
  return (
    <>
      <Paper shadow="sm" p="lg">
        <Flex gap="lg" align="center">
        <Avatar src={`http://localhost:3000/api/campaign${userInfo?.img}`} size={120} radius={120} />
        <Stack spacing="xs" align="flex-start">
            <Text ta="center" fz="lg" weight={500}>
              {userInfo.username}
            </Text>
            <Text ta="left" c="dimmed" fz="sm">
              {userInfo.email}
            </Text>

            <Button variant="light" leftIcon={<IconSend size={18} />} fullWidth>
              Send message
            </Button>
          </Stack>
        </Flex>
        <Flex gap="sm" align="center" wrap="wrap" justify="flex-start" mt="lg">
          <Button variant="light" size="sm" leftIcon={<IconSend size={18} />} radius="md">
            {editableLender.type}
          </Button>

          <Button variant="light" size="sm" leftIcon={<IconSend size={18} />} radius="md">
            {editableLender.interest}% Interest
          </Button> 
          <Button variant="light" size="sm" leftIcon={<IconSend size={18} />} radius="md">
            {editableLender.bonus}TK Bonus
          </Button>

          <Button variant="light" size="sm" leftIcon={<IconSend size={18} />} radius="md">
            {monthsRemaining} Months
          </Button>

          <Button variant="light" size="sm" leftIcon={<IconSend size={18} />} radius="md">
            1000 Loan
          </Button>

          <Button variant="light" size="sm" leftIcon={<IconSend size={18} />} radius="md">
            {total} Lend
          </Button>

          <Button variant="light" size="sm" leftIcon={<IconSend size={18} />} radius="md" onClick={handleClick}>
            Review: {review}/10
          </Button>
          <Progress value={(review / 10) * 100} color={review > 8 ? 'darkgreen' : 'red'} radius="md" size="lg" mt="10px" />
        </Flex>
        <br />

        {lender.final  && lender.username != username && (
          <Button disabled size="xl">
            Confirmed Lender
          </Button>
        )}

        { lender.username == username && !own && (
          <Button variant="filled" size="lg" radius="md" fullWidth onClick={() => setIsModalOpen(true)}>
            Update BID
          </Button>
        )}
        {!lender.final && !final && own && (
          <Button variant="filled" size="lg" radius="md" fullWidth onClick={confirmlend}>
            Confirm Lender
          </Button>
        )}
      </Paper>
      {/* Modal for updating lender info */}
      <Modal opened={isModalOpen} onClose={() => setIsModalOpen(false)} title="Update Lender Info">
        <Stack spacing="md">
          {/* <TextInput
            label="Username"
            value={editableLender.username}
            onChange={(event) => setEditableLender({ ...editableLender, username: event.currentTarget.value })}
          /> */}
      
        <Input
          label="Deadline Date"
          type="date"
         value={editableLender.deadlineDate ? formatDate(editableLender.deadlineDate) : ''} 
          onChange={(event) => setEditableLender({ ...editableLender, deadlineDate: event.currentTarget.value })}
        />
        {!lender.final && !final && (

          <NumberInput
            label="Interest Rate"
            value={editableLender.interest}
            onChange={(value) => setEditableLender({ ...editableLender, interest: value ?? editableLender.interest })}
          />
        )}
          {!lender.final && !final  && (
         <TextInput
          label="Bonus"
          value={editableLender.bonus}
          onChange={(event) => setEditableLender({ ...editableLender, bonus: event.currentTarget.value })}
        />
        )}
       {!lender.final && !final && (

        <Select
        label="Type"
        value={editableLender.type}
        onChange={(value) => setEditableLender({ ...editableLender, type: value ?? editableLender.type })}
        data={[
          { value: 'EMI', label: 'EMI' },
          { value: 'One Time', label: 'One Time' },
          // { value: 'Wish', label: 'Wish' }
        ]}
      />
      )}

          {/* <TextInput
            label="Gap"
            value={editableLender.gap}
            onChange={(event) => setEditableLender({ ...editableLender, gap: event.currentTarget.value })}
          /> */}
          {/* <TextInput
            label="Created At"
            value={editableLender.createdAt}
            onChange={(event) => setEditableLender({ ...editableLender, createdAt: event.currentTarget.value })}
          /> */}
        </Stack>

        <Button fullWidth mt="md" onClick={updatebid}>
          Submit Update
        </Button>
      </Modal>
    </>
  );
};
export default LenderCard;