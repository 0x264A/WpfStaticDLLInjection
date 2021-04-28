using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using Microsoft.Win32;

namespace WpfStaticDLLInjection
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            tbPEFile.AddHandler(RichTextBox.DragOverEvent, new DragEventHandler(TextBox_DragOver), true);
            tbPEFile.AddHandler(RichTextBox.DropEvent, new DragEventHandler(PE_TextBox_Drop), true);
            tbDLLFile.AddHandler(RichTextBox.DragOverEvent, new DragEventHandler(TextBox_DragOver), true);
            tbDLLFile.AddHandler(RichTextBox.DropEvent, new DragEventHandler(DLL_TextBox_Drop), true);
        }
        private void TextBox_DragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.All;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = false;
        }

        private void PE_TextBox_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] docPath = (string[])e.Data.GetData(DataFormats.FileDrop);
                tbPEFile.Text = docPath[0];
            }
        }
        private void DLL_TextBox_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] docPath = (string[])e.Data.GetData(DataFormats.FileDrop);
                tbDLLFile.Text = docPath[0];
            }
        }
        private void Button_Click_OpenPEFile(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
               tbPEFile.Text = openFileDialog.FileName;
        }
        private void Button_Click_OpenDLLFile(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                tbDLLFile.Text = openFileDialog.FileName;
        }
        private void Button_Click_InjectDLL(object sender, RoutedEventArgs e)
        {
            if((tbPEFile.Text == "") || (tbDLLFile.Text == "" )|| tbDLLFuncName.Text == "" )
            {
                MessageBox.Show("Please enter all necessary information");
                return;
            }
            PEStructLoader PE = new PEStructLoader(tbPEFile.Text);
            string dllName = tbDLLFile.Text.Substring(tbPEFile.Text.LastIndexOf("\\")+1);
            PE.StaticDLLInjectionByAddingSection(dllName, tbDLLFuncName.Text);
            tbPEFile.Text = "";
            tbDLLFile.Text = "";
            tbDLLFuncName.Text = "";
            MessageBox.Show("Done");
        }
    }
}
