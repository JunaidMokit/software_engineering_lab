import React, { useState } from 'react';
import { Container, Title, Text, Input, Button, Group, Stack, Paper, Grid } from '@mantine/core';

const Transaction = () => {
  const [total, setTotal] = useState<string>('৳');
  const [paid, setPaid] = useState<string>('৳');
  const [due, setDue] = useState<string>('৳');
  const [interest, setInterest] = useState<string>('৳');
  const [returnDate, setReturnDate] = useState<string>('2024-06-23');
  const [emi, setEmi] = useState<string>('৳');
  const [payable, setPayable] = useState<string>('৳');

  return (
    <Container size="sm" my="lg">
      {/* Title */}
      <Paper shadow="xs" p="md" withBorder>
        <Title align="center" order={2}>Transaction Page</Title>
        <Text align="center" mt="sm">Sabbir wants 100k loan</Text>

        {/* Form Group */}
        <Stack spacing="md" mt="lg">
          <Grid>
            <Grid.Col span={4}>
              <Text>Total</Text>
            </Grid.Col>
            <Grid.Col span={6}>
              <Input value={total} onChange={(e) => setTotal(e.currentTarget.value)} />
            </Grid.Col>

            <Grid.Col span={4}>
              <Text>Paid</Text>
            </Grid.Col>
            <Grid.Col span={6}>
              <Input value={paid} onChange={(e) => setPaid(e.currentTarget.value)} />
            </Grid.Col>

            <Grid.Col span={4}>
              <Text>Due</Text>
            </Grid.Col>
            <Grid.Col span={6}>
              <Input value={due} onChange={(e) => setDue(e.currentTarget.value)} />
            </Grid.Col>

            <Grid.Col span={4}>
              <Text>Interest</Text>
            </Grid.Col>
            <Grid.Col span={6}>
              <Input value={interest} onChange={(e) => setInterest(e.currentTarget.value)} />
            </Grid.Col>

            <Grid.Col span={4}>
              <Text>Return</Text>
            </Grid.Col>
            <Grid.Col span={6}>
              <Input type="date" value={returnDate} onChange={(e) => setReturnDate(e.currentTarget.value)} />
            </Grid.Col>

            <Grid.Col span={4}>
              <Text>EMI</Text>
            </Grid.Col>
            <Grid.Col span={6}>
              <Input value={emi} onChange={(e) => setEmi(e.currentTarget.value)} />
            </Grid.Col>

            <Grid.Col span={4}>
              <Text>Payable</Text>
            </Grid.Col>
            <Grid.Col span={6}>
              <Input value={payable} onChange={(e) => setPayable(e.currentTarget.value)} />
            </Grid.Col>
          </Grid>
        </Stack>

        {/* Action Buttons */}
        <Group position="center" mt="xl">
          <Button variant="outline">Payment</Button>
          <Button>Save</Button>
        </Group>
      </Paper>
    </Container>
  );
};

export default Transaction;
