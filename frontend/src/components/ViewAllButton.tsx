import React from 'react';
import { Link } from 'react-router-dom';

const ViewAllButton: React.FC = () => {
  return (
    <Link
      to="/identities"
      className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition font-medium"
    >
      View All Identities →
    </Link>
  );
};

export default ViewAllButton;
