export default {
  up(queryInterface, Sequelize) {
    return Promise.all([
      queryInterface.addColumn('Users', 'roleId', {
        allowNull: true,
        type: Sequelize.INTEGER,
        defaultValue: 1,
        onDelete: 'CASCADE',
        references: {
          model: 'Roles',
          key: 'id',
        },
      }),
    ]);
  },

  down(queryInterface, Sequelize) {
    return Promise.all([queryInterface.removeColumn('Users', 'roleId')]);
  },
};
