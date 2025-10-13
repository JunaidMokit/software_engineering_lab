import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Modal, Button, Text } from '@mantine/core';

const DonationSuccessPage = () => {
    const navigate = useNavigate();
    const { id } = useParams();
    const [isModalOpen, setIsModalOpen] = useState(true);

    useEffect(() => {
        const timer = setTimeout(() => {
            setIsModalOpen(false);
            navigate(`/loans/${id}`);
        }, 1000);

        return () => clearTimeout(timer); 
    }, [id, navigate]);

    return (
        <>
            <Modal
                opened={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                title="Payment Successful!"
                centered
                withCloseButton={false}
            >
                <Text size="md">Redirecting to Loan details...</Text>
            </Modal>
        </>
    );
};

export default DonationSuccessPage;
