module.exports = {
    extends: ['@jahia/eslint-config'],
    rules: {
        // Internal presentational components pass props locally; we don't require
        // PropTypes across the board (the GraphQL layer is the real contract).
        'react/prop-types': 'off'
    }
};
