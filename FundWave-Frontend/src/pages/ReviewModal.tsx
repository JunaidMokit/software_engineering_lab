import React, { useState } from 'react';
import { Modal, Stack, Textarea, Button, Rating, Group } from '@mantine/core';

const ReviewModal = ({ opened, onClose, loanId, onReviewSubmit }) => {
    const [reviewMessage, setReviewMessage] = useState('');
    const [reviewStar, setReviewStar] = useState(0);
    const username=localStorage.getItem('username');

    const submitReview = async (loanId, reviewMessage, reviewStar) => {
    const response = await fetch(`http://localhost:3000/api/loans/review`, { 
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username,
            id: loanId,
            message: reviewMessage,
            rating: reviewStar,
        }),
    });
    if (!response.ok) {
        throw new Error('Failed to submit review');
    }

    return await response.json(); // Return the response data if needed
};


    const handleSubmit = async () => {
        try {
            await submitReview(loanId, reviewMessage, reviewStar);
            // Optionally, trigger a refresh of reviews or call a parent callback
            onReviewSubmit();
            // Reset form
            setReviewMessage('');
            setReviewStar(0);
            onClose(); // Close the modal
        } catch (error) {
            // Handle the error (show notification, etc.)
        }
    };

    return (
        <Modal opened={opened} onClose={onClose} title="Submit a Review">
            <Stack>
                <Textarea
                    placeholder="Write your review here"
                    label="Review Message"
                    value={reviewMessage}
                    onChange={(event) => setReviewMessage(event.currentTarget.value)}
                />
                <Rating
                    value={reviewStar}
                    onChange={setReviewStar}
                    size="lg"
                    label="Star Rating"
                    max={10}
                />
                <Group position="right">
                    <Button onClick={handleSubmit}>Submit Review</Button>
                </Group>
            </Stack>
        </Modal>
    );
};

export default ReviewModal;
