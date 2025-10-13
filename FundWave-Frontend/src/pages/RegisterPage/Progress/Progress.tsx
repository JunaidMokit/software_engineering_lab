import React from 'react';
import { Loader, createStyles } from '@mantine/core'; // Use Mantine's Loader and createStyles
import './Progress.css';

const useStyles = createStyles((theme) => ({
  root: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    height: '100vh', // Ensures the loader is centered vertically
  },
  progress: {
    margin: theme.spacing.md, // Mantine's spacing system
  },
}));

function Progress({ className }) {
  const { classes } = useStyles();

  return (
    <div className={`${classes.root} ${className}`}>
      <Loader className={classes.progress} size="lg" />
    </div>
  );
}

export default Progress;
