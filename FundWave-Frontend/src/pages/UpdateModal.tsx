import {
    Modal,
    Button,
    TextInput,
    NumberInput,
    Stack,
    Group,
    Text,
  } from '@mantine/core';
  import { DatePicker,DateInput } from '@mantine/dates';  // Correct import for DatePicker
  import { useForm } from '@mantine/form';
  import { useEffect, useState } from 'react';
  import { notifications } from '@mantine/notifications';
 import { ICampaign } from '../types';
  
  const UpdateModal = ({ id, opened, onClose }: { id: String; opened: boolean; onClose: () => void }) => {
    const [loading, setLoading] = useState(false);
    const [campaign, setCampaign] = useState([]);
    const [amount, setAmount] = useState(0);
    const [deadline, setDeadline] = useState(new Date());
    
    const fetchCampaign = async () => {
        try{
            const response = await fetch(`http://localhost:3000/api/campaign/${id}`);
            if (!response.ok) {
            throw new Error('Failed to fetch campaign');
            }

            const data = await response.json();
            setDeadline(new Date(data.deadlineDate));
            setAmount(data.amount);
            console.log(deadline);
            console.log(amount);

        } catch (error) {
            console.log(error);
            // notifications.show({
            // title: 'Error',
            // message: error.message,
            // color: 'red',
            // });
        }
        }

        useEffect(() => {
            fetchCampaign();
        }, [id]);
  
    const form = useForm({
      initialValues: {
        target: amount,
        deadline: deadline,
      },
    });

    const handleUpdate = async (values: any) => {
      setLoading(true);
      try {
        const response = await fetch(`http://localhost:3000/api/campaign/${id}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            amount: values.target,
            deadlineDate: values.deadline,
          }),
        });
  
        if (!response.ok) {
          throw new Error('Failed to update the campaign');
        }
  
        notifications.show({
          title: 'Success',
          message: 'Campaign updated successfully!',
          color: 'green',
        });
  
        onClose(); // Close the modal after a successful update
      } catch (error) {
        notifications.show({
          title: 'Error',
          message: error.message,
          color: 'red',
        });
      } finally {
        setLoading(false);
      }
    };

    const handleMarkAsEnd = async () => {
      setLoading(true);
  
      try {
        const response = await fetch(`http://localhost:3000/api/campaign/markAsCompleted/${id}`, {
          method: 'PUT',
        });
  
        if (!response.ok) {
          throw new Error('Failed to mark the campaign as END');
        }
  
        notifications.show({
          title: 'Success',
          message: 'Campaign marked as END!',
          color: 'green',
        });
  
        onClose(); // Close the modal after a successful update
      } catch (error) {
        notifications.show({
          title: 'Error',
          message: error.message,
          color: 'red',
        });
      } finally {
        setLoading(false);
      }
    };
  
    return (
      <Modal
        opened={opened}
        onClose={onClose}
        title="Update Campaign"
        size="lg"
        centered
      >
        <Stack spacing="md">
        <NumberInput
                    label="Update Target Amount"
                    placeholder="Enter new target amount"
                    min={0}
                    value={amount}
                    onChange={(value) => {
                        setAmount(value);
                        form.setFieldValue('target', value); // Update form value
                    }}
                />
                <Text>Change New Deadline Date</Text>
                <DatePicker
                    value={deadline ? new Date(deadline) : null} // Ensure value is Date or null
                    placeholder="Pick a new deadline date"
                    onChange={(date) => {
                        setDeadline(date);
                        form.setFieldValue('deadline', date); // Update form value
                    }}
                />

          <Group position="apart">
            <Button onClick={handleMarkAsEnd} color="red" loading={loading}>
              Mark as END
            </Button>
  
            <Button onClick={form.onSubmit(handleUpdate)} loading={loading}>
              Update Campaign
            </Button>
          </Group>
        </Stack>
      </Modal>
    );
  };
  
  export default UpdateModal;
  