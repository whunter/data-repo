require "spec_helper"

RSpec.describe 'collection view page', type: :feature do
  let(:user) { FactoryGirl.create(:user) }
  let(:collection) do
    c = FactoryGirl.build(:collection)
    c.apply_depositor_metadata(user.user_key)
    c.save
    c
  end

  before do
    OmniAuth.config.add_mock(:cas, { uid: user.uid })
    visit new_user_session_path
  end

  it 'allows user to edit a collection from the collection view' do
    visit '/collections/' + collection.id
    click_link "Edit"
    fill_in "Title", with: "Edited Title"
    click_button "update_submit"
    expect(page).to have_content "Edited Title"
  end

end
