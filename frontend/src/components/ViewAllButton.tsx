/**
 * ViewAllButton Component
 *
 * A simple navigation button that links to the full identities list page.
 * Used on the Dashboard to provide quick access to the complete identity list.
 *
 * Styling:
 *   - Blue primary button style
 *   - Hover state with darker blue
 *   - Right arrow indicating navigation
 *
 * Usage:
 *   <ViewAllButton />  // Renders "View All Identities →" link button
 */
import React from 'react';
import { Link } from 'react-router-dom';

/**
 * Navigation button linking to the identities list page.
 */
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
