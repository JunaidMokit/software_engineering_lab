import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Modal, Button, Text } from '@mantine/core';

const DonationSuccessPage = () => {
    const navigate = useNavigate();
    const { id } = useParams();
    const [isModalOpen, setIsModalOpen] = useState(true);

    useEffect(() => {
        // Redirect to the campaign details page after a delay (e.g., 3 seconds)
        const timer = setTimeout(() => {
            setIsModalOpen(false); // Close modal after 3 seconds
            navigate(`/campaigns/${id}`);
        }, 1000);

        return () => clearTimeout(timer); // Cleanup timeout if the component unmounts
    }, [id, navigate]);

    return (
        <>
            <Modal
                opened={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                title="Donation Successful!"
                centered
                withCloseButton={false}
            >
                <Text size="md">Redirecting to campaign details...</Text>
            </Modal>
        </>
    );
};

export default DonationSuccessPage;
