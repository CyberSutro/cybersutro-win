#Requires -Version 5.1
<#
    Cybersutro win - Interfaz gráfica (WPF)
    Se construye dinámicamente a partir de Get-CSWModule (ver docs/CONTRATO.md).
    Uso (desde el lanzador, en hilo STA, con core y módulos ya importados):
        . .\ui\CSW.Gui.ps1
        Start-CSWGui -RootPath $root
    Compatible con Windows PowerShell 5.1 y PowerShell 7.
    Estilo: claro corporativo. Fuentes: Segoe UI, Segoe Fluent Icons / Segoe MDL2 Assets
    (iconos) y Cascadia Mono / Consolas (registro), con alternativas automáticas.
#>

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# ---------------------------------------------------------------------------
# Recursos compartidos (paleta, logotipo y estilos). Se fusionan en la ventana
# principal y en los diálogos.
# ---------------------------------------------------------------------------
$script:CSWGuiStylesXaml = @'
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <SolidColorBrush x:Key="Accent" Color="#0B5CAD"/>
  <SolidColorBrush x:Key="AccentSoft" Color="#E8F0FA"/>
  <SolidColorBrush x:Key="Ink" Color="#0F172A"/>
  <SolidColorBrush x:Key="Ink2" Color="#334155"/>
  <SolidColorBrush x:Key="Muted" Color="#64748B"/>
  <SolidColorBrush x:Key="Line" Color="#E2E8F0"/>
  <FontFamily x:Key="IconFont">Segoe Fluent Icons, Segoe MDL2 Assets</FontFamily>
  <FontFamily x:Key="MonoFont">Cascadia Mono, Consolas</FontFamily>

  <!-- Marca: escudo con pulso de diagnóstico -->
  <PathGeometry x:Key="LogoShield" Figures="M32,3 L56,11.5 L56,30 C56,45.5 45.6,56.6 32,61 C18.4,56.6 8,45.5 8,30 L8,11.5 Z"/>
  <DrawingImage x:Key="LogoImage">
    <DrawingImage.Drawing>
      <DrawingGroup>
        <GeometryDrawing Brush="#00FFFFFF" Geometry="M0,0 L64,0 L64,64 L0,64 Z"/>
        <GeometryDrawing Geometry="M32,3 L56,11.5 L56,30 C56,45.5 45.6,56.6 32,61 C18.4,56.6 8,45.5 8,30 L8,11.5 Z">
          <GeometryDrawing.Brush>
            <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
              <GradientStop Color="#2A86E0" Offset="0"/>
              <GradientStop Color="#0B5CAD" Offset="0.55"/>
              <GradientStop Color="#073F78" Offset="1"/>
            </LinearGradientBrush>
          </GeometryDrawing.Brush>
        </GeometryDrawing>
        <GeometryDrawing Brush="#22FFFFFF" Geometry="M32,3 L8,11.5 L8,30 C8,45.5 18.4,56.6 32,61 Z"/>
        <GeometryDrawing Geometry="M13,32 L21.5,32 L26,21 L32.5,43 L37,32 L44.5,32">
          <GeometryDrawing.Pen>
            <Pen Brush="White" Thickness="4.4" StartLineCap="Round" EndLineCap="Round" LineJoin="Round"/>
          </GeometryDrawing.Pen>
        </GeometryDrawing>
        <GeometryDrawing Brush="#5CD6FF">
          <GeometryDrawing.Geometry><EllipseGeometry Center="49.5,32" RadiusX="3.7" RadiusY="3.7"/></GeometryDrawing.Geometry>
        </GeometryDrawing>
      </DrawingGroup>
    </DrawingImage.Drawing>
  </DrawingImage>

  <!-- Botones -->
  <Style x:Key="BtnBase" TargetType="Button">
    <Setter Property="Background" Value="#0B5CAD"/>
    <Setter Property="Foreground" Value="White"/>
    <Setter Property="BorderBrush" Value="Transparent"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="14,7"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="SnapsToDevicePixels" Value="True"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Button">
          <Grid>
            <Border x:Name="fr" BorderBrush="#7FB0E6" BorderThickness="2" CornerRadius="8" Margin="-3" Opacity="0"/>
            <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6"/>
            <Border x:Name="ov" Background="#0F172A" Opacity="0" CornerRadius="6"/>
            <ContentPresenter Margin="{TemplateBinding Padding}" HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
                              VerticalAlignment="Center" RecognizesAccessKey="True"/>
          </Grid>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="ov" Property="Opacity" Value="0.09"/></Trigger>
            <Trigger Property="IsPressed" Value="True"><Setter TargetName="ov" Property="Opacity" Value="0.18"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="fr" Property="Opacity" Value="1"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/><Setter Property="Cursor" Value="Arrow"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style x:Key="BtnPrimary" TargetType="Button" BasedOn="{StaticResource BtnBase}"/>
  <Style x:Key="BtnSecondary" TargetType="Button" BasedOn="{StaticResource BtnBase}">
    <Setter Property="Background" Value="White"/>
    <Setter Property="Foreground" Value="#1E293B"/>
    <Setter Property="BorderBrush" Value="#CBD5E1"/>
  </Style>
  <Style x:Key="BtnDanger" TargetType="Button" BasedOn="{StaticResource BtnBase}">
    <Setter Property="Background" Value="#B91C1C"/>
    <Setter Property="Padding" Value="12,3"/>
  </Style>
  <Style x:Key="BtnDangerLg" TargetType="Button" BasedOn="{StaticResource BtnBase}">
    <Setter Property="Background" Value="#B91C1C"/>
  </Style>
  <Style x:Key="BtnLight" TargetType="Button" BasedOn="{StaticResource BtnBase}">
    <Setter Property="Background" Value="White"/>
    <Setter Property="Foreground" Value="#0B5CAD"/>
    <Setter Property="Padding" Value="20,11"/>
    <Setter Property="FontSize" Value="14"/>
  </Style>
  <Style x:Key="BtnDark" TargetType="Button" BasedOn="{StaticResource BtnBase}">
    <Setter Property="Background" Value="#1E293B"/>
    <Setter Property="Foreground" Value="#CBD5E1"/>
    <Setter Property="BorderBrush" Value="#334155"/>
    <Setter Property="Padding" Value="9,3"/>
    <Setter Property="FontWeight" Value="Normal"/>
    <Setter Property="FontSize" Value="12"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#2B3A52"/><Setter Property="Foreground" Value="White"/></Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="BtnGhost" TargetType="Button" BasedOn="{StaticResource BtnBase}">
    <Setter Property="Background" Value="Transparent"/>
    <Setter Property="Foreground" Value="#475569"/>
    <Setter Property="Padding" Value="8,4"/>
    <Setter Property="FontWeight" Value="Normal"/>
  </Style>
  <Style x:Key="BtnIcon" TargetType="Button" BasedOn="{StaticResource BtnGhost}"/>
  <Style x:Key="BtnTile" TargetType="Button">
    <Setter Property="Background" Value="White"/>
    <Setter Property="BorderBrush" Value="#E2E8F0"/>
    <Setter Property="Foreground" Value="#0F172A"/>
    <Setter Property="Padding" Value="14,12"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Button">
          <Grid>
            <Border x:Name="sh" Background="White" CornerRadius="10" Opacity="0.35">
              <Border.Effect><DropShadowEffect Color="#0B3A6E" BlurRadius="16" ShadowDepth="2" Direction="270" Opacity="0.14"/></Border.Effect>
            </Border>
            <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="10" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center"/>
            </Border>
          </Grid>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="bd" Property="BorderBrush" Value="#8DB4E2"/>
              <Setter TargetName="sh" Property="Opacity" Value="1"/>
            </Trigger>
            <Trigger Property="IsPressed" Value="True"><Setter TargetName="bd" Property="Background" Value="#F1F6FC"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#0B5CAD"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/><Setter Property="Cursor" Value="Arrow"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <!-- Tarjeta con sombra suave (la sombra va en una capa sin texto para no difuminarlo) -->
  <Style x:Key="CardCC" TargetType="ContentControl">
    <Setter Property="Padding" Value="18,16"/>
    <Setter Property="Focusable" Value="False"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ContentControl">
          <Grid>
            <Border Background="White" CornerRadius="10">
              <Border.Effect><DropShadowEffect Color="#0F172A" BlurRadius="12" ShadowDepth="1" Direction="270" Opacity="0.06"/></Border.Effect>
            </Border>
            <Border Background="White" BorderBrush="#E2E8F0" BorderThickness="1" CornerRadius="10" Padding="{TemplateBinding Padding}">
              <ContentPresenter/>
            </Border>
          </Grid>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style x:Key="Card" TargetType="Border">
    <Setter Property="Background" Value="White"/>
    <Setter Property="BorderBrush" Value="#E2E8F0"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="CornerRadius" Value="10"/>
    <Setter Property="Padding" Value="18,16"/>
  </Style>

  <!-- Tipografía -->
  <Style x:Key="PageTitle" TargetType="TextBlock">
    <Setter Property="FontSize" Value="22"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="Foreground" Value="#0F172A"/>
  </Style>
  <Style x:Key="CardTitle" TargetType="TextBlock">
    <Setter Property="FontSize" Value="14.5"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="Foreground" Value="#0F172A"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
  </Style>
  <Style x:Key="SectionTitle" TargetType="TextBlock">
    <Setter Property="FontSize" Value="15"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="Foreground" Value="#0F172A"/>
    <Setter Property="Margin" Value="0,22,0,10"/>
  </Style>
  <Style x:Key="FieldLabel" TargetType="TextBlock">
    <Setter Property="FontSize" Value="12"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="Foreground" Value="#475569"/>
    <Setter Property="Margin" Value="0,10,0,5"/>
  </Style>
  <Style x:Key="Glyph" TargetType="TextBlock">
    <Setter Property="FontFamily" Value="Segoe Fluent Icons, Segoe MDL2 Assets"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
  </Style>

  <!-- Campos -->
  <Style TargetType="TextBox">
    <Setter Property="Foreground" Value="#0F172A"/>
    <Setter Property="Background" Value="White"/>
    <Setter Property="BorderBrush" Value="#CBD5E1"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="9,6"/>
    <Setter Property="VerticalContentAlignment" Value="Center"/>
    <Setter Property="CaretBrush" Value="#0B5CAD"/>
    <Setter Property="SelectionBrush" Value="#0B5CAD"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="TextBox">
          <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6">
            <ScrollViewer x:Name="PART_ContentHost" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#94A3B8"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#0B5CAD"/><Setter TargetName="bd" Property="BorderThickness" Value="1.5"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="bd" Property="Background" Value="#F1F5F9"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style TargetType="PasswordBox">
    <Setter Property="Foreground" Value="#0F172A"/>
    <Setter Property="Background" Value="White"/>
    <Setter Property="BorderBrush" Value="#CBD5E1"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="9,6"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="PasswordBox">
          <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6">
            <ScrollViewer x:Name="PART_ContentHost"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#94A3B8"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#0B5CAD"/><Setter TargetName="bd" Property="BorderThickness" Value="1.5"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style TargetType="CheckBox">
    <Setter Property="Foreground" Value="#1E293B"/>
    <Setter Property="VerticalContentAlignment" Value="Center"/>
    <Setter Property="Cursor" Value="Hand"/>
  </Style>
  <Style TargetType="ComboBox">
    <Setter Property="Padding" Value="9,6"/>
    <Setter Property="MinHeight" Value="34"/>
    <Setter Property="VerticalContentAlignment" Value="Center"/>
  </Style>

  <!-- Barras de desplazamiento finas (sirven sobre fondo claro y oscuro) -->
  <Style x:Key="SbThumb" TargetType="Thumb">
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Thumb">
          <Border x:Name="t" CornerRadius="4" Background="#7094A3B8" Margin="2"/>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="t" Property="Background" Value="#B094A3B8"/></Trigger>
            <Trigger Property="IsDragging" Value="True"><Setter TargetName="t" Property="Background" Value="#D064748B"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style TargetType="ScrollBar">
    <Setter Property="Background" Value="Transparent"/>
    <Setter Property="Width" Value="11"/>
    <Setter Property="MinWidth" Value="11"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ScrollBar">
          <Grid Background="Transparent">
            <Track x:Name="PART_Track" IsDirectionReversed="True">
              <Track.Thumb><Thumb Style="{StaticResource SbThumb}"/></Track.Thumb>
            </Track>
          </Grid>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
    <Style.Triggers>
      <Trigger Property="Orientation" Value="Horizontal">
        <Setter Property="Width" Value="Auto"/>
        <Setter Property="MinWidth" Value="0"/>
        <Setter Property="Height" Value="11"/>
        <Setter Property="MinHeight" Value="11"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="ScrollBar">
              <Grid Background="Transparent">
                <Track x:Name="PART_Track" IsDirectionReversed="False">
                  <Track.Thumb><Thumb Style="{StaticResource SbThumb}"/></Track.Thumb>
                </Track>
              </Grid>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Trigger>
    </Style.Triggers>
  </Style>

  <!-- Navegación lateral -->
  <Style x:Key="NavItem" TargetType="ListBoxItem">
    <Setter Property="Foreground" Value="#334155"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="Margin" Value="10,1"/>
    <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ListBoxItem">
          <Grid>
            <Border x:Name="bd" Background="Transparent" CornerRadius="7" Padding="12,8,10,8">
              <ContentPresenter VerticalAlignment="Center" HorizontalAlignment="Stretch"/>
            </Border>
            <Border x:Name="bar" Width="3" HorizontalAlignment="Left" Background="#0B5CAD" CornerRadius="2" Margin="0,8" Visibility="Collapsed"/>
          </Grid>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#F1F5F9"/></Trigger>
            <Trigger Property="IsSelected" Value="True">
              <Setter TargetName="bd" Property="Background" Value="#E8F0FA"/>
              <Setter TargetName="bar" Property="Visibility" Value="Visible"/>
              <Setter Property="Foreground" Value="#0B5CAD"/>
              <Setter Property="FontWeight" Value="SemiBold"/>
            </Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#93C5FD"/><Setter TargetName="bd" Property="BorderThickness" Value="1"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style x:Key="NavHeader" TargetType="ListBoxItem">
    <Setter Property="Focusable" Value="False"/>
    <Setter Property="IsEnabled" Value="False"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ListBoxItem">
          <ContentPresenter Margin="24,14,10,5"/>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style x:Key="NavPill" TargetType="Border">
    <Setter Property="Background" Value="#F1F5F9"/>
    <Setter Property="CornerRadius" Value="9"/>
    <Setter Property="Padding" Value="7,0,7,1"/>
    <Setter Property="MinWidth" Value="24"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
    <Style.Triggers>
      <DataTrigger Binding="{Binding IsSelected, RelativeSource={RelativeSource AncestorType=ListBoxItem}}" Value="True">
        <Setter Property="Background" Value="#D2E2F5"/>
      </DataTrigger>
    </Style.Triggers>
  </Style>

  <!-- Registro -->
  <Style x:Key="LogItem" TargetType="ListBoxItem">
    <Setter Property="Padding" Value="0"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ListBoxItem">
          <Border x:Name="bd" Background="Transparent" Padding="4,1">
            <ContentPresenter/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#16FFFFFF"/></Trigger>
            <Trigger Property="IsSelected" Value="True"><Setter TargetName="bd" Property="Background" Value="#1E3A5F"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <DataTemplate x:Key="LogTpl">
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <TextBlock Text="{Binding Time}" Foreground="#64748B" Margin="0,0,10,0" VerticalAlignment="Center"/>
      <Border x:Name="tg" Grid.Column="1" Width="46" CornerRadius="3" Margin="0,1,10,1" Background="#1E293B" VerticalAlignment="Center">
        <TextBlock x:Name="tt" Text="{Binding Tag}" FontFamily="Segoe UI" FontSize="9.5" FontWeight="SemiBold" Foreground="#94A3B8"
                   HorizontalAlignment="Center" Margin="0,0,0,1"/>
      </Border>
      <TextBlock x:Name="t" Grid.Column="2" Text="{Binding Msg}" Foreground="#CBD5E1" TextWrapping="NoWrap" VerticalAlignment="Center"/>
    </Grid>
    <DataTemplate.Triggers>
      <DataTrigger Binding="{Binding Level}" Value="Ok">
        <Setter TargetName="t" Property="Foreground" Value="#86EFAC"/><Setter TargetName="tt" Property="Foreground" Value="#4ADE80"/><Setter TargetName="tg" Property="Background" Value="#2216A34A"/>
      </DataTrigger>
      <DataTrigger Binding="{Binding Level}" Value="Warn">
        <Setter TargetName="t" Property="Foreground" Value="#FCD34D"/><Setter TargetName="tt" Property="Foreground" Value="#FBBF24"/><Setter TargetName="tg" Property="Background" Value="#26F59E0B"/>
      </DataTrigger>
      <DataTrigger Binding="{Binding Level}" Value="Error">
        <Setter TargetName="t" Property="Foreground" Value="#FCA5A5"/><Setter TargetName="tt" Property="Foreground" Value="#F87171"/><Setter TargetName="tg" Property="Background" Value="#2EEF4444"/>
      </DataTrigger>
      <DataTrigger Binding="{Binding Level}" Value="Step">
        <Setter TargetName="t" Property="Foreground" Value="#67E8F9"/><Setter TargetName="tt" Property="Foreground" Value="#22D3EE"/><Setter TargetName="tg" Property="Background" Value="#2206B6D4"/>
      </DataTrigger>
      <DataTrigger Binding="{Binding Level}" Value="Data">
        <Setter TargetName="t" Property="Foreground" Value="#94A3B8"/><Setter TargetName="tt" Property="Foreground" Value="#64748B"/><Setter TargetName="tg" Property="Background" Value="#00000000"/>
      </DataTrigger>
    </DataTemplate.Triggers>
  </DataTemplate>

  <Style TargetType="ToolTip">
    <Setter Property="Background" Value="#0F172A"/>
    <Setter Property="Foreground" Value="White"/>
    <Setter Property="BorderThickness" Value="0"/>
    <Setter Property="Padding" Value="9,6"/>
    <Setter Property="MaxWidth" Value="380"/>
    <Setter Property="ContentTemplate">
      <Setter.Value>
        <DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap"/></DataTemplate>
      </Setter.Value>
    </Setter>
  </Style>
</ResourceDictionary>
'@

# ---------------------------------------------------------------------------
# Ventana principal
# ---------------------------------------------------------------------------
$script:CSWGuiWindowXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Cybersutro win" Width="1280" Height="800" MinWidth="1024" MinHeight="640"
        WindowStartupLocation="CenterScreen" Background="#F3F5F9"
        FontFamily="Segoe UI" FontSize="13" Foreground="#0F172A"
        UseLayoutRounding="True" SnapsToDevicePixels="True" TextOptions.TextFormattingMode="Display">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="58"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="34"/>
    </Grid.RowDefinitions>

    <!-- Barra superior -->
    <Border Grid.Row="0" Background="White" BorderBrush="#E2E8F0" BorderThickness="0,0,0,1">
      <Grid Margin="18,0">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <Image Source="{StaticResource LogoImage}" Width="36" Height="36" RenderOptions.BitmapScalingMode="HighQuality"/>
          <StackPanel Margin="10,0,0,0" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="Cybersutro" FontSize="17" FontWeight="Bold" Foreground="#0B5CAD"/>
              <TextBlock Text=" win" FontSize="17" FontWeight="Light" Foreground="#0F172A"/>
              <Border Margin="10,1,0,0" Background="#EEF2F7" CornerRadius="4" Padding="6,1,6,2" VerticalAlignment="Center">
                <TextBlock x:Name="VersionText" Text="v1.0.0" FontSize="10.5" FontWeight="SemiBold" Foreground="#475569"/>
              </Border>
            </StackPanel>
            <TextBlock Text="Soporte técnico para Windows" FontSize="11" Foreground="#64748B" Margin="0,-1,0,0"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Background="#F1F5F9" CornerRadius="15" Padding="12,5" Margin="0,0,10,0">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="&#xE7F4;" FontFamily="{StaticResource IconFont}" FontSize="13" Foreground="#475569" VerticalAlignment="Center"/>
              <TextBlock x:Name="ComputerText" Margin="8,0,0,0" Text="PC" FontWeight="SemiBold" Foreground="#1E293B" VerticalAlignment="Center"/>
            </StackPanel>
          </Border>
          <Border x:Name="AdminBadge" Background="#E8F5EC" BorderBrush="#A7D9B8" BorderThickness="1" CornerRadius="15" Padding="12,4">
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="AdminGlyph" Text="&#xE7EF;" FontFamily="{StaticResource IconFont}" FontSize="13" Foreground="#15803D" VerticalAlignment="Center"/>
              <TextBlock x:Name="AdminText" Margin="8,0,0,0" Text="Administrador" FontWeight="SemiBold" Foreground="#15803D" VerticalAlignment="Center"/>
            </StackPanel>
          </Border>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Cuerpo -->
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="252"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Navegación -->
      <Border Background="White" BorderBrush="#E2E8F0" BorderThickness="0,0,1,0">
        <DockPanel>
          <Border DockPanel.Dock="Bottom" BorderBrush="#E2E8F0" BorderThickness="0,1,0,0" Padding="20,10,16,12">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <TextBlock Text="&#xE823;" FontFamily="{StaticResource IconFont}" FontSize="13" Foreground="#94A3B8" VerticalAlignment="Top" Margin="0,2,10,0"/>
              <StackPanel Grid.Column="1">
                <TextBlock x:Name="NavFooter1" Text="" FontSize="11.5" Foreground="#475569"/>
                <TextBlock x:Name="NavFooter2" Text="" FontSize="11" Foreground="#94A3B8" TextTrimming="CharacterEllipsis"/>
              </StackPanel>
            </Grid>
          </Border>
          <ListBox x:Name="NavList" Margin="0,10,0,0" BorderThickness="0" Background="Transparent"
                   ItemContainerStyle="{StaticResource NavItem}" ScrollViewer.HorizontalScrollBarVisibility="Disabled"/>
        </DockPanel>
      </Border>

      <!-- Contenido + registro -->
      <Grid Grid.Column="1">
        <Grid.RowDefinitions>
          <RowDefinition Height="*" MinHeight="220"/>
          <RowDefinition x:Name="SplitRow" Height="6"/>
          <RowDefinition x:Name="LogRow" Height="150" MinHeight="90"/>
        </Grid.RowDefinitions>

        <!-- Inicio -->
        <ScrollViewer x:Name="DashView" Grid.Row="0" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
          <ScrollViewer.RenderTransform><TranslateTransform/></ScrollViewer.RenderTransform>
          <StackPanel Margin="28,22,28,22">
            <Grid Margin="0,0,0,16">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <StackPanel>
                <TextBlock Text="Inicio" Style="{StaticResource PageTitle}"/>
                <TextBlock Text="Estado del equipo, accesos rápidos y datos del servicio" Foreground="#64748B" Margin="0,2,0,0" TextTrimming="CharacterEllipsis"/>
              </StackPanel>
              <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Bottom">
                <TextBlock x:Name="DateText" Foreground="#64748B" VerticalAlignment="Center" Margin="0,0,10,0"/>
                <Button x:Name="RefreshBtn" Style="{StaticResource BtnSecondary}" Padding="10,5" FontWeight="Normal" ToolTip="Actualizar el estado del equipo (F5)">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE72C;" FontFamily="{StaticResource IconFont}" FontSize="12" VerticalAlignment="Center"/>
                    <TextBlock Text="Actualizar" Margin="7,0,0,0" FontSize="12.5"/>
                  </StackPanel>
                </Button>
              </StackPanel>
            </Grid>

            <!-- Indicadores del equipo -->
            <UniformGrid x:Name="KpiGrid" Columns="5" Margin="0,0,-12,0"/>

            <!-- Reparación rápida -->
            <Border CornerRadius="12" Margin="0,16,0,0" ClipToBounds="True">
              <Border.Background>
                <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                  <GradientStop Color="#0D66BF" Offset="0"/>
                  <GradientStop Color="#0B5CAD" Offset="0.45"/>
                  <GradientStop Color="#073F78" Offset="1"/>
                </LinearGradientBrush>
              </Border.Background>
              <Grid>
                <Path Data="{StaticResource LogoShield}" Fill="White" Opacity="0.06" Stretch="Uniform" Width="230" Height="230"
                      HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,-40,150,-40" IsHitTestVisible="False"/>
                <Grid Margin="24,20">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel>
                    <StackPanel Orientation="Horizontal">
                      <Border Width="38" Height="38" CornerRadius="19" Background="#26FFFFFF">
                        <TextBlock Text="&#xE945;" FontFamily="{StaticResource IconFont}" FontSize="17" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                      </Border>
                      <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
                        <TextBlock Text="Reparación rápida en un clic" FontSize="18" FontWeight="SemiBold" Foreground="White"/>
                        <TextBlock Text="Ejecuta en orden los pasos de mantenimiento más habituales y genera el informe del cliente." Foreground="#D6E4F5" TextWrapping="Wrap"/>
                      </StackPanel>
                    </StackPanel>
                    <WrapPanel x:Name="QuickSteps" Margin="0,14,0,0"/>
                    <StackPanel Orientation="Horizontal" Margin="0,4,0,0">
                      <TextBlock Text="&#xE946;" FontFamily="{StaticResource IconFont}" FontSize="12" Foreground="#BFD3EC" VerticalAlignment="Center"/>
                      <TextBlock Text="Se crea un punto de restauración antes de empezar. Puede tardar entre 15 y 60 minutos (DISM y SFC)." Foreground="#BFD3EC" FontSize="12" Margin="7,0,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                  </StackPanel>
                  <Button x:Name="QuickBtn" Grid.Column="1" Style="{StaticResource BtnLight}" VerticalAlignment="Center" Margin="20,0,0,0">
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="&#xE768;" FontFamily="{StaticResource IconFont}" FontSize="13" VerticalAlignment="Center" Margin="0,1,8,0"/>
                      <TextBlock Text="Iniciar reparación"/>
                    </StackPanel>
                  </Button>
                </Grid>
              </Grid>
            </Border>

            <!-- Accesos rápidos -->
            <Grid>
              <TextBlock Text="Accesos rápidos" Style="{StaticResource SectionTitle}"/>
              <TextBlock Text="Las acciones piden confirmación cuando corresponde" Foreground="#94A3B8" FontSize="12" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,0,0,11"/>
            </Grid>
            <UniformGrid x:Name="QuickTiles" Columns="4" Margin="0,0,-12,0"/>

            <!-- Resumen y servicio -->
            <Grid Margin="0,22,0,0">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="16"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>

              <ContentControl Style="{StaticResource CardCC}">
                <StackPanel>
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                    <TextBlock Text="&#xE7F4;" Style="{StaticResource Glyph}" Foreground="#0B5CAD" FontSize="15" Margin="0,0,10,0"/>
                    <TextBlock Text="Ficha del equipo" Style="{StaticResource CardTitle}"/>
                  </StackPanel>
                  <TextBlock x:Name="SummaryLoading" Text="Cargando información del equipo…" Foreground="#64748B" Margin="0,4"/>
                  <Grid x:Name="SummaryGrid">
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="150"/>
                      <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                  </Grid>
                </StackPanel>
              </ContentControl>

              <ContentControl Grid.Column="2" Style="{StaticResource CardCC}">
                <StackPanel>
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,2">
                    <TextBlock Text="&#xE77B;" Style="{StaticResource Glyph}" Foreground="#0B5CAD" FontSize="15" Margin="0,0,10,0"/>
                    <TextBlock Text="Datos del servicio" Style="{StaticResource CardTitle}"/>
                  </StackPanel>
                  <TextBlock Text="Aparecen en el informe que se entrega al cliente." Foreground="#64748B" FontSize="12"/>
                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="*"/>
                      <ColumnDefinition Width="12"/>
                      <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel>
                      <TextBlock Text="Técnico" Style="{StaticResource FieldLabel}"/>
                      <TextBox x:Name="TechBox"/>
                    </StackPanel>
                    <StackPanel Grid.Column="2">
                      <TextBlock Text="Cliente" Style="{StaticResource FieldLabel}"/>
                      <TextBox x:Name="ClientBox"/>
                    </StackPanel>
                  </Grid>
                  <TextBlock Text="Observaciones" Style="{StaticResource FieldLabel}"/>
                  <TextBox x:Name="NotesBox" Height="78" AcceptsReturn="True" TextWrapping="Wrap" VerticalContentAlignment="Top" VerticalScrollBarVisibility="Auto"/>
                  <WrapPanel Margin="0,14,0,0">
                    <Button x:Name="ReportBtn" Style="{StaticResource BtnPrimary}" Margin="0,0,8,6">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE8A5;" FontFamily="{StaticResource IconFont}" FontSize="12" VerticalAlignment="Center" Margin="0,1,8,0"/>
                        <TextBlock Text="Generar informe HTML"/>
                      </StackPanel>
                    </Button>
                    <Button x:Name="FolderBtn" Style="{StaticResource BtnSecondary}" Margin="0,0,0,6">
                      <StackPanel Orientation="Horizontal">
                        <TextBlock Text="&#xE838;" FontFamily="{StaticResource IconFont}" FontSize="12" VerticalAlignment="Center" Margin="0,1,8,0"/>
                        <TextBlock Text="Abrir carpeta de datos"/>
                      </StackPanel>
                    </Button>
                  </WrapPanel>
                </StackPanel>
              </ContentControl>
            </Grid>

            <!-- Módulos -->
            <TextBlock Text="Módulos" Style="{StaticResource SectionTitle}"/>
            <UniformGrid x:Name="ModuleTiles" Columns="4" Margin="0,0,-12,0"/>
          </StackPanel>
        </ScrollViewer>

        <!-- Vista de módulo -->
        <Grid x:Name="ModuleView" Grid.Row="0" Visibility="Collapsed" Margin="28,22,12,0">
          <Grid.RenderTransform><TranslateTransform/></Grid.RenderTransform>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <Grid Margin="0,0,16,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Border Width="46" Height="46" CornerRadius="11" VerticalAlignment="Top">
              <Border.Background>
                <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                  <GradientStop Color="#EEF4FB" Offset="0"/>
                  <GradientStop Color="#DCE8F7" Offset="1"/>
                </LinearGradientBrush>
              </Border.Background>
              <TextBlock x:Name="ModGlyph" FontFamily="{StaticResource IconFont}" FontSize="21" Foreground="#0B5CAD" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <StackPanel Grid.Column="1" Margin="14,0,0,0">
              <TextBlock x:Name="ModTitle" Style="{StaticResource PageTitle}" TextTrimming="CharacterEllipsis"/>
              <TextBlock x:Name="ModDesc" Foreground="#475569" TextWrapping="Wrap" Margin="0,2,0,0"/>
              <TextBlock x:Name="ModMeta" Foreground="#94A3B8" FontSize="12" Margin="0,3,0,0" TextTrimming="CharacterEllipsis"/>
            </StackPanel>
          </Grid>
          <Grid Grid.Row="1" Margin="0,16,16,14">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*" MaxWidth="440"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid>
              <TextBox x:Name="SearchBox" Padding="34,7,32,7"/>
              <TextBlock Text="&#xE721;" FontFamily="{StaticResource IconFont}" Foreground="#94A3B8" Margin="12,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
              <TextBlock x:Name="SearchHint" Text="Buscar acción…  (Ctrl+F)" Foreground="#94A3B8" Margin="35,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
              <Button x:Name="SearchClearBtn" Style="{StaticResource BtnGhost}" HorizontalAlignment="Right" Margin="0,0,3,0" Padding="7,4" Visibility="Collapsed" ToolTip="Borrar búsqueda (Esc)">
                <TextBlock Text="&#xE711;" FontFamily="{StaticResource IconFont}" FontSize="10"/>
              </Button>
            </Grid>
            <TextBlock x:Name="ModCount" Grid.Column="1" HorizontalAlignment="Right" VerticalAlignment="Center" Foreground="#64748B"/>
          </Grid>
          <ScrollViewer x:Name="CardsScroll" Grid.Row="2" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel>
              <WrapPanel x:Name="CardsPanel" Margin="1,2,0,10"/>
              <StackPanel x:Name="NoResults" Visibility="Collapsed" HorizontalAlignment="Center" Margin="0,40,16,30">
                <Border Width="68" Height="68" CornerRadius="34" Background="#E8F0FA" HorizontalAlignment="Center">
                  <TextBlock Text="&#xE721;" FontFamily="{StaticResource IconFont}" FontSize="26" Foreground="#0B5CAD" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Border>
                <TextBlock Text="Sin resultados" FontSize="16" FontWeight="SemiBold" HorizontalAlignment="Center" Margin="0,14,0,0"/>
                <TextBlock x:Name="NoResultsText" Foreground="#64748B" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap" MaxWidth="440" Margin="0,4,0,0"/>
                <Button x:Name="NoResultsBtn" Style="{StaticResource BtnSecondary}" HorizontalAlignment="Center" Margin="0,16,0,0">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE894;" FontFamily="{StaticResource IconFont}" FontSize="11" VerticalAlignment="Center" Margin="0,1,8,0"/>
                    <TextBlock Text="Limpiar búsqueda"/>
                  </StackPanel>
                </Button>
              </StackPanel>
            </StackPanel>
          </ScrollViewer>
        </Grid>

        <GridSplitter x:Name="LogSplitter" Grid.Row="1" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" ResizeDirection="Rows" Cursor="SizeNS" ShowsPreview="False" ToolTip="Arrastre para cambiar el alto del registro">
          <GridSplitter.Template>
            <ControlTemplate TargetType="GridSplitter">
              <Grid Background="#F3F5F9">
                <Border Width="44" Height="3" CornerRadius="2" Background="#CBD5E1" HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Grid>
            </ControlTemplate>
          </GridSplitter.Template>
        </GridSplitter>

        <!-- Consola de registro -->
        <Border x:Name="LogPanel" Grid.Row="2" Background="#0F172A" CornerRadius="10" Margin="16,0,16,12">
          <DockPanel>
            <Grid DockPanel.Dock="Top" Margin="14,7,8,5">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="&#xE756;" FontFamily="{StaticResource IconFont}" Foreground="#64748B" FontSize="12" VerticalAlignment="Center"/>
                <TextBlock Text="Registro en vivo" Foreground="#E2E8F0" FontWeight="SemiBold" Margin="8,0,0,0" FontSize="12"/>
                <Border Background="#1E293B" CornerRadius="8" Padding="7,0,7,1" Margin="10,0,0,0" VerticalAlignment="Center">
                  <TextBlock x:Name="LogCount" Foreground="#94A3B8" FontSize="10.5" VerticalAlignment="Center"/>
                </Border>
              </StackPanel>
              <StackPanel Grid.Column="1" Orientation="Horizontal">
                <CheckBox x:Name="AutoScrollChk" Content="Auto-desplazar" IsChecked="True" Foreground="#94A3B8" FontSize="11" Margin="0,0,12,0" VerticalAlignment="Center"/>
                <Button x:Name="LogCopyBtn" Style="{StaticResource BtnDark}" Margin="0,0,6,0" ToolTip="Copiar el registro (o las líneas seleccionadas)">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE8C8;" FontFamily="{StaticResource IconFont}" FontSize="11" VerticalAlignment="Center" Margin="0,1,6,0"/>
                    <TextBlock Text="Copiar"/>
                  </StackPanel>
                </Button>
                <Button x:Name="LogClearBtn" Style="{StaticResource BtnDark}" Margin="0,0,6,0" ToolTip="Limpiar el panel (el archivo de log se conserva)">
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="&#xE74D;" FontFamily="{StaticResource IconFont}" FontSize="11" VerticalAlignment="Center" Margin="0,1,6,0"/>
                    <TextBlock Text="Limpiar"/>
                  </StackPanel>
                </Button>
                <Button x:Name="LogHideBtn" Style="{StaticResource BtnDark}" ToolTip="Ocultar el registro (Ctrl+L)">
                  <TextBlock Text="&#xE70D;" FontFamily="{StaticResource IconFont}" FontSize="11" VerticalAlignment="Center" Margin="0,2,0,1"/>
                </Button>
              </StackPanel>
            </Grid>
            <ListBox x:Name="LogList" Background="Transparent" BorderThickness="0" Margin="8,0,4,8"
                     FontFamily="{StaticResource MonoFont}" FontSize="12" SelectionMode="Extended"
                     ItemContainerStyle="{StaticResource LogItem}" ItemTemplate="{StaticResource LogTpl}"
                     VirtualizingStackPanel.IsVirtualizing="True" VirtualizingStackPanel.VirtualizationMode="Recycling"
                     ScrollViewer.CanContentScroll="True" ScrollViewer.HorizontalScrollBarVisibility="Auto">
              <ListBox.Resources>
                <SolidColorBrush x:Key="{x:Static SystemColors.ControlBrushKey}" Color="Transparent"/>
              </ListBox.Resources>
            </ListBox>
          </DockPanel>
        </Border>
      </Grid>
    </Grid>

    <!-- Barra de estado -->
    <Border Grid.Row="2" Background="White" BorderBrush="#E2E8F0" BorderThickness="0,1,0,0">
      <Grid Margin="16,0,10,0">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <Ellipse x:Name="StatusDot" Width="8" Height="8" Fill="#15803D" VerticalAlignment="Center"/>
          <TextBlock x:Name="StatusText" Text="Listo" Margin="8,0,0,0" Foreground="#334155" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
        </StackPanel>
        <ProgressBar x:Name="Progress" Grid.Column="1" Width="150" Height="4" Margin="12,0" IsIndeterminate="False"
                     Foreground="#0B5CAD" Background="#E2E8F0" BorderThickness="0" Visibility="Hidden" VerticalAlignment="Center"/>
        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" Margin="4,0,14,0" ToolTip="Tiempo de la última acción">
          <TextBlock Text="&#xE916;" FontFamily="{StaticResource IconFont}" Foreground="#94A3B8" FontSize="12" VerticalAlignment="Center"/>
          <TextBlock x:Name="ElapsedText" Text="00:00" Margin="6,0,0,0" Foreground="#334155" FontFamily="{StaticResource MonoFont}" VerticalAlignment="Center"/>
        </StackPanel>
        <TextBlock x:Name="CounterText" Grid.Column="3" Text="Acciones en la sesión: 0" Foreground="#64748B" VerticalAlignment="Center" Margin="0,0,8,0"/>
        <Button x:Name="LogToggleBtn" Grid.Column="4" Style="{StaticResource BtnGhost}" Padding="8,3" Margin="0,0,6,0" VerticalAlignment="Center" ToolTip="Mostrar u ocultar el registro (Ctrl+L)">
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="&#xE756;" FontFamily="{StaticResource IconFont}" FontSize="12" VerticalAlignment="Center"/>
            <TextBlock x:Name="LogToggleText" Text="Ocultar registro" Margin="6,0,0,0" FontSize="12" VerticalAlignment="Center"/>
            <Border x:Name="LogUnreadBadge" Visibility="Collapsed" Background="#0B5CAD" CornerRadius="8" Padding="6,0,6,1" Margin="7,0,0,0" VerticalAlignment="Center">
              <TextBlock x:Name="LogUnreadText" Foreground="White" FontSize="10.5" FontWeight="SemiBold"/>
            </Border>
          </StackPanel>
        </Button>
        <Button x:Name="StopBtn" Grid.Column="5" Style="{StaticResource BtnDanger}" Visibility="Collapsed" VerticalAlignment="Center" FontSize="12">
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="&#xE71A;" FontFamily="{StaticResource IconFont}" FontSize="10" VerticalAlignment="Center" Margin="0,1,6,0"/>
            <TextBlock Text="Detener"/>
          </StackPanel>
        </Button>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# Tarjeta de acción (se parsea una vez por acción; usa DynamicResource porque se crea
# fuera del árbol de la ventana). La sombra de elevación vive en una capa sin texto.
$script:CSWGuiCardXaml = @'
<ContentControl xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                Width="336" Height="184" Margin="0,0,14,14" Focusable="False">
  <ContentControl.Template>
    <ControlTemplate TargetType="ContentControl">
      <Grid>
        <Border x:Name="sh" Background="White" CornerRadius="10" Opacity="0.3">
          <Border.Effect><DropShadowEffect Color="#0B3A6E" BlurRadius="18" ShadowDepth="3" Direction="270" Opacity="0.13"/></Border.Effect>
        </Border>
        <Border x:Name="bd" Background="White" BorderBrush="#E2E8F0" BorderThickness="1" CornerRadius="10" Padding="16,14,16,14">
          <ContentPresenter/>
        </Border>
        <Border x:Name="ac" Height="3" VerticalAlignment="Top" CornerRadius="10,10,0,0" Background="#0B5CAD" Margin="1,1,1,0" Opacity="0"/>
      </Grid>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd" Property="BorderBrush" Value="#8DB4E2"/>
          <Setter TargetName="sh" Property="Opacity" Value="1"/>
          <Setter TargetName="ac" Property="Opacity" Value="1"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </ContentControl.Template>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <Border Width="34" Height="34" CornerRadius="8" Background="#EEF4FB" VerticalAlignment="Top">
        <TextBlock x:Name="TIcon" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="15" Foreground="#0B5CAD" HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <TextBlock x:Name="TName" Grid.Column="1" Margin="12,0,8,0" FontSize="14" FontWeight="SemiBold" Foreground="#0F172A"
                 TextWrapping="Wrap" TextTrimming="CharacterEllipsis" MaxHeight="40" VerticalAlignment="Center"/>
      <Border x:Name="Badge" Grid.Column="2" CornerRadius="10" Padding="7,2,9,3" VerticalAlignment="Top" Margin="0,2,0,0">
        <StackPanel Orientation="Horizontal">
          <Ellipse x:Name="BDot" Width="6" Height="6" VerticalAlignment="Center"/>
          <TextBlock x:Name="TBadge" FontSize="11" FontWeight="SemiBold" Margin="5,0,0,0" VerticalAlignment="Center"/>
        </StackPanel>
      </Border>
    </Grid>
    <TextBlock x:Name="TDesc" Grid.Row="1" Margin="0,10,0,0" TextWrapping="Wrap" TextTrimming="CharacterEllipsis"
               Foreground="#475569" FontSize="12.5" LineHeight="18" LineStackingStrategy="BlockLineHeight"/>
    <Grid Grid.Row="2" Margin="0,8,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <WrapPanel x:Name="Flags" VerticalAlignment="Bottom" Margin="0,0,8,0"/>
      <Button x:Name="BRun" Grid.Column="1" Style="{DynamicResource BtnPrimary}" Padding="13,6" FontSize="12.5" VerticalAlignment="Bottom">
        <StackPanel Orientation="Horizontal">
          <TextBlock Text="&#xE768;" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="10.5" VerticalAlignment="Center" Margin="0,1,7,0"/>
          <TextBlock Text="Ejecutar"/>
        </StackPanel>
      </Button>
    </Grid>
  </Grid>
</ContentControl>
'@

# Indicador del panel de inicio
$script:CSWGuiKpiXaml = @'
<ContentControl xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                Style="{DynamicResource CardCC}" Padding="16,14,16,14" Margin="0,0,12,0">
  <StackPanel>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border x:Name="KIconBg" Width="30" Height="30" CornerRadius="8" Background="#E8F0FA">
        <TextBlock x:Name="KIcon" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="15" Foreground="#0B5CAD" HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <TextBlock x:Name="KLabel" Grid.Column="1" Margin="10,0,0,0" VerticalAlignment="Center" Foreground="#64748B" FontWeight="SemiBold" FontSize="12" TextTrimming="CharacterEllipsis"/>
    </Grid>
    <TextBlock x:Name="KValue" Text="—" FontSize="21" FontWeight="SemiBold" Foreground="#0F172A" Margin="0,12,0,0" TextTrimming="CharacterEllipsis"/>
    <TextBlock x:Name="KSub" Text="Cargando…" FontSize="11.5" Foreground="#64748B" Margin="0,1,0,0" TextTrimming="CharacterEllipsis"/>
    <Grid x:Name="KBar" Height="6" Margin="0,10,0,0" Visibility="Hidden">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="0*"/>
        <ColumnDefinition Width="100*"/>
      </Grid.ColumnDefinitions>
      <Border Grid.ColumnSpan="2" Background="#E2E8F0" CornerRadius="3"/>
      <Border x:Name="KFill" Background="#0B5CAD" CornerRadius="3"/>
    </Grid>
  </StackPanel>
</ContentControl>
'@

# Acceso directo (inicio y módulos)
$script:CSWGuiTileXaml = @'
<Button xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Style="{DynamicResource BtnTile}" Margin="0,0,12,12">
  <Grid>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="*"/>
      <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>
    <Border x:Name="TIconBg" Width="38" Height="38" CornerRadius="9" Background="#E8F0FA" VerticalAlignment="Center">
      <TextBlock x:Name="TIcon" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="17" Foreground="#0B5CAD" HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
    <StackPanel Grid.Column="1" Margin="12,0,6,0" VerticalAlignment="Center">
      <TextBlock x:Name="TTitle" FontWeight="SemiBold" FontSize="13.5" Foreground="#0F172A" TextTrimming="CharacterEllipsis"/>
      <TextBlock x:Name="TSub" FontSize="12" Foreground="#64748B" TextTrimming="CharacterEllipsis" Margin="0,1,0,0"/>
    </StackPanel>
    <TextBlock x:Name="TArrow" Grid.Column="2" Text="&#xE76C;" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="11" Foreground="#94A3B8" VerticalAlignment="Center"/>
  </Grid>
</Button>
'@

# Diálogo de datos de una acción
$script:CSWGuiDialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Datos de la acción" Width="480" SizeToContent="Height" ResizeMode="NoResize" WindowStyle="None"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" Background="White" BorderBrush="#94A3B8" BorderThickness="1"
        FontFamily="Segoe UI" FontSize="13" Foreground="#0F172A" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <DockPanel>
    <Border DockPanel.Dock="Top" Height="4" Background="#0B5CAD"/>
    <Border DockPanel.Dock="Bottom" Background="#F8FAFC" BorderBrush="#E2E8F0" BorderThickness="0,1,0,0" Padding="20,12">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="DCancel" Content="Cancelar" IsCancel="True" Style="{DynamicResource BtnSecondary}" Margin="0,0,8,0" MinWidth="96"/>
        <Button x:Name="DOk" Content="Continuar" IsDefault="True" Style="{DynamicResource BtnPrimary}" MinWidth="112"/>
      </StackPanel>
    </Border>
    <StackPanel Margin="22,18,22,18">
      <Grid x:Name="DHeader" Background="Transparent">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Border Width="40" Height="40" CornerRadius="20" Background="#E8F0FA" VerticalAlignment="Top">
          <TextBlock Text="&#xE70F;" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="16" Foreground="#0B5CAD" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Border>
        <StackPanel Grid.Column="1" Margin="14,0,0,0">
          <TextBlock x:Name="DTitle" FontSize="16" FontWeight="SemiBold" TextWrapping="Wrap"/>
          <TextBlock x:Name="DDesc" Foreground="#475569" TextWrapping="Wrap" Margin="0,3,0,0" LineHeight="18"/>
        </StackPanel>
      </Grid>
      <Border Height="1" Background="#E2E8F0" Margin="0,14,0,2"/>
      <ScrollViewer MaxHeight="440" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
        <StackPanel x:Name="Fields" Margin="0,0,2,4"/>
      </ScrollViewer>
    </StackPanel>
  </DockPanel>
</Window>
'@

# Mensajes y confirmaciones (sustituye a MessageBox con la misma semántica)
$script:CSWGuiMessageXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Cybersutro win" Width="470" SizeToContent="Height" ResizeMode="NoResize" WindowStyle="None"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" Background="White" BorderBrush="#94A3B8" BorderThickness="1"
        FontFamily="Segoe UI" FontSize="13" Foreground="#0F172A" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <DockPanel>
    <Border x:Name="MStripe" DockPanel.Dock="Top" Height="4" Background="#0B5CAD"/>
    <Border DockPanel.Dock="Bottom" Background="#F8FAFC" BorderBrush="#E2E8F0" BorderThickness="0,1,0,0" Padding="20,12">
      <StackPanel x:Name="MButtons" Orientation="Horizontal" HorizontalAlignment="Right"/>
    </Border>
    <Grid Margin="22,20,22,20">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border x:Name="MIconBg" Width="40" Height="40" CornerRadius="20" Background="#E8F0FA" VerticalAlignment="Top">
        <TextBlock x:Name="MIcon" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" FontSize="18" Foreground="#0B5CAD" HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <StackPanel Grid.Column="1" Margin="16,0,0,0">
        <TextBlock x:Name="MTitle" FontSize="16" FontWeight="SemiBold" TextWrapping="Wrap" Margin="0,1,0,0"/>
        <ScrollViewer MaxHeight="380" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Margin="0,7,0,0">
          <TextBlock x:Name="MText" TextWrapping="Wrap" Foreground="#334155" LineHeight="19"/>
        </ScrollViewer>
      </StackPanel>
    </Grid>
  </DockPanel>
</Window>
'@

# Scripts que se ejecutan en el runspace de trabajo
$script:CSWGuiInitScript = @'
param([hashtable]$State, [string]$RootPath, [string]$ModulePath)
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $RootPath 'core\CSW.Core.psm1') -Global -Force -DisableNameChecking
Initialize-CSWCore -State $State -RootPath $RootPath
$n = 0
if ($ModulePath -and (Test-Path -LiteralPath $ModulePath)) {
    foreach ($f in (Get-ChildItem -LiteralPath $ModulePath -Filter *.psm1 | Sort-Object Name)) {
        try { Import-Module $f.FullName -Global -Force -DisableNameChecking -ErrorAction Stop; $n++ }
        catch { Write-CSWLog ("No se pudo cargar el módulo {0} en segundo plano: {1}" -f $f.BaseName, $_.Exception.Message) -Level Error }
    }
}
$n
'@

$script:CSWGuiActionScript = @'
param([string]$FullId, [hashtable]$Params)
if ($null -eq $Params) { $Params = @{} }
$a = Get-CSWAction -FullId $FullId
if (-not $a) { Write-CSWLog "Acción no encontrada: $FullId" -Level Error; return 'Error' }
Invoke-CSWAction -Action $a -Params $Params
'@

$script:CSWGuiQuickScript = @'
Invoke-CSWQuickRepair
'@

$script:CSWGuiReportScript = @'
Export-CSWReport -Open
'@

# Resumen del equipo + indicadores del panel (solo lectura; se ejecuta en segundo plano)
$script:CSWGuiSummaryScript = @'
param([string]$CorePath)
Import-Module $CorePath -Force -DisableNameChecking
$s = Get-CSWSystemSummary
foreach ($k in @($s.Keys)) {
    $v = $s[$k]
    if ($v -is [datetime]) { $v = $v.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
    [pscustomobject]@{ K = [string]$k; V = [string]$v }
}
$kpi = @{}
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $kpi.RamTotalKB = [double]$os.TotalVisibleMemorySize
    $kpi.RamFreeKB = [double]$os.FreePhysicalMemory
    $kpi.BootTicks = ([datetime]$os.LastBootUpTime).Ticks
}
catch { }
try {
    $cpus = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
    if ($cpus.Count) {
        $kpi.CpuName = [string]$cpus[0].Name
        $kpi.CpuCores = [int](($cpus | Measure-Object -Property NumberOfCores -Sum).Sum)
        $kpi.CpuThreads = [int](($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
        $loads = @($cpus | Where-Object { $null -ne $_.LoadPercentage } | ForEach-Object { [double]$_.LoadPercentage })
        if ($loads.Count) { $kpi.CpuLoad = [int][Math]::Round((($loads | Measure-Object -Average).Average)) }
    }
}
catch { }
try {
    $sd = $env:SystemDrive
    if (-not $sd) { $sd = 'C:' }
    $d = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $sd) -ErrorAction Stop
    if ($d -and $d.Size) { $kpi.DiskId = [string]$d.DeviceID; $kpi.DiskSize = [double]$d.Size; $kpi.DiskFree = [double]$d.FreeSpace }
}
catch { }
[pscustomobject]@{ K = '__kpi'; V = ''; Kpi = $kpi }
'@

# Accesos rápidos del inicio (se ejecutan con el mismo mecanismo que las tarjetas)
$script:CSWGuiQuickActions = @(
    @{ Id = 'Hardware.FullHealthCheck'; Title = 'Salud de hardware'; Sub = 'Revisión completa con puntuación'; Glyph = 0xE950; Fg = '#0B5CAD'; Bg = '#E8F0FA' }
    @{ Id = 'SecurityAudit.FullAudit'; Title = 'Auditoría completa'; Sub = 'Ciberseguridad con informe HTML'; Glyph = 0xE9D5; Fg = '#4338CA'; Bg = '#ECEBFB' }
    @{ Id = 'Network.ConnectivityTest'; Title = 'Test de conectividad'; Sub = 'Red, puerta de enlace, DNS e Internet'; Glyph = 0xE701; Fg = '#0E7490'; Bg = '#E3F4F7' }
    @{ Id = 'Disk.CleanTemp'; Title = 'Limpiar temporales'; Sub = 'Libera espacio en disco'; Glyph = 0xE74D; Fg = '#B45309'; Bg = '#FDF1E2' }
)

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
function ConvertTo-CSWGuiBrush {
    param([string]$Hex)
    $b = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Hex)
    $b.Freeze()
    return $b
}

function Get-CSWGuiProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-CSWGuiGlyph {
    param([string]$Key)
    $k = ([string]$Key).ToLowerInvariant()
    $code = 0xE713
    if ($k -match 'home|inicio') { $code = 0xE80F }
    elseif ($k -match 'audit') { $code = 0xE9D5 }
    elseif ($k -match 'hardware') { $code = 0xE950 }
    elseif ($k -match 'diag|pulse|health|salud') { $code = 0xE9D9 }
    elseif ($k -match 'net|red|wifi|lan') { $code = 0xE839 }
    elseif ($k -match 'repair|repar|wrench|tool') { $code = 0xE90F }
    elseif ($k -match 'disk|disco|drive|storage|hdd') { $code = 0xEDA2 }
    elseif ($k -match 'secur|segur|shield|defender') { $code = 0xEA18 }
    elseif ($k -match 'print|impres') { $code = 0xE749 }
    elseif ($k -match 'user|usuar|backup|copia|people') { $code = 0xE716 }
    elseif ($k -match 'soft|app|program|package') { $code = 0xE7B8 }
    return [string][char]$code
}

function Get-CSWGuiNavGroup {
    # Agrupa los módulos por su Order: <30 diagnóstico, <50 mantenimiento, <60 seguridad, resto gestión
    param($Order)
    $o = 50
    try { $o = [int]$Order } catch { }
    if ($o -lt 30) { return 'DIAGNÓSTICO' }
    if ($o -lt 50) { return 'MANTENIMIENTO' }
    if ($o -lt 60) { return 'SEGURIDAD' }
    return 'GESTIÓN'
}

function Invoke-CSWGuiFade {
    # Transición sutil al cambiar de vista (opacidad + desplazamiento de 6 px, 140 ms)
    param($Element)
    try {
        $dur = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(140))
        $ease = New-Object System.Windows.Media.Animation.QuadraticEase
        $ease.EasingMode = 'EaseOut'
        $a = New-Object System.Windows.Media.Animation.DoubleAnimation(0.0, 1.0, $dur)
        $a.EasingFunction = $ease
        $Element.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $a)
        $tt = $Element.RenderTransform
        if ($tt -is [System.Windows.Media.TranslateTransform] -and -not $tt.IsFrozen) {
            $b = New-Object System.Windows.Media.Animation.DoubleAnimation(6.0, 0.0, $dur)
            $b.EasingFunction = $ease
            $tt.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, $b)
        }
    }
    catch { }
}

function Get-CSWGuiLogoBitmap {
    # Icono de ventana generado en tiempo de ejecución a partir del logotipo vectorial
    param([int]$Size = 64)
    $g = $script:CSWGui
    $img = $g.Styles['LogoImage']
    if (-not $img) { return $null }
    $dv = New-Object System.Windows.Media.DrawingVisual
    $dc = $dv.RenderOpen()
    $dc.PushTransform((New-Object System.Windows.Media.ScaleTransform(($Size / 64.0), ($Size / 64.0))))
    $dc.DrawDrawing($img.Drawing)
    $dc.Pop()
    $dc.Close()
    $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($Size, $Size, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($dv)
    $rtb.Freeze()
    return [System.Windows.Media.Imaging.BitmapFrame]::Create($rtb)
}

function Add-CSWGuiLog {
    param([string]$Message, [string]$Level = 'Info', $Time)
    $g = $script:CSWGui
    if ($null -eq $Time) { $Time = Get-Date }
    $tag = switch ($Level) { 'Ok' { 'OK' } 'Warn' { 'AVISO' } 'Error' { 'ERROR' } 'Step' { 'PASO' } 'Data' { 'DATO' } default { 'INFO' } }
    $ts = '{0:HH:mm:ss}' -f $Time
    [void]$g.LogItems.Add([pscustomobject]@{ Text = ('{0}  {1}' -f $ts, $Message); Level = $Level; Time = $ts; Tag = $tag; Msg = $Message })
    if (-not $g.LogVisible) {
        $g.LogUnread++
        if ($Level -eq 'Error') { $g.LogUnreadLevel = 'Error' }
        elseif ($Level -eq 'Warn' -and $g.LogUnreadLevel -ne 'Error') { $g.LogUnreadLevel = 'Warn' }
    }
}

function Update-CSWGuiLogToggle {
    $g = $script:CSWGui
    if ($g.LogVisible) {
        $g.C.LogToggleText.Text = 'Ocultar registro'
        $g.C.LogUnreadBadge.Visibility = 'Collapsed'
        return
    }
    $g.C.LogToggleText.Text = 'Mostrar registro'
    if ($g.LogUnread -gt 0) {
        $txt = [string]$g.LogUnread
        if ($g.LogUnread -gt 999) { $txt = '999+' }
        $g.C.LogUnreadText.Text = $txt
        $col = '#0B5CAD'
        if ($g.LogUnreadLevel -eq 'Error') { $col = '#B91C1C' } elseif ($g.LogUnreadLevel -eq 'Warn') { $col = '#B45309' }
        $g.C.LogUnreadBadge.Background = ConvertTo-CSWGuiBrush $col
        $g.C.LogUnreadBadge.Visibility = 'Visible'
    }
    else { $g.C.LogUnreadBadge.Visibility = 'Collapsed' }
}

function Set-CSWGuiLogVisible {
    # Muestra u oculta el panel de registro; el estado se recuerda durante la sesión
    param([bool]$Visible)
    $g = $script:CSWGui
    if ($Visible) {
        $h = [double]$g.LogHeight
        if ($h -lt 90) { $h = 150 }
        $g.C.LogRow.MinHeight = 90
        $g.C.LogRow.Height = New-Object System.Windows.GridLength($h)
        $g.C.SplitRow.Height = New-Object System.Windows.GridLength(6)
        $g.C.LogPanel.Visibility = 'Visible'
        $g.C.LogSplitter.Visibility = 'Visible'
        $g.LogUnread = 0; $g.LogUnreadLevel = ''
    }
    else {
        if ($g.C.LogRow.ActualHeight -ge 90) { $g.LogHeight = $g.C.LogRow.ActualHeight }
        $g.C.LogRow.MinHeight = 0
        $g.C.LogRow.Height = New-Object System.Windows.GridLength(0)
        $g.C.SplitRow.Height = New-Object System.Windows.GridLength(0)
        $g.C.LogPanel.Visibility = 'Collapsed'
        $g.C.LogSplitter.Visibility = 'Collapsed'
    }
    $g.LogVisible = $Visible
    try { $global:CSW.GuiLogVisible = $Visible; $global:CSW.GuiLogHeight = $g.LogHeight } catch { }
    Update-CSWGuiLogToggle
    if ($Visible -and $g.LogItems.Count -gt 0 -and $g.C.AutoScrollChk.IsChecked) {
        $g.C.LogList.ScrollIntoView($g.LogItems[$g.LogItems.Count - 1])
        Reset-CSWGuiLogHScroll
    }
}

function Update-CSWGuiLogView {
    $g = $script:CSWGui
    $max = 5000
    if ($g.LogItems.Count -gt $max) {
        $keep = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
        $start = $g.LogItems.Count - 4500
        for ($i = $start; $i -lt $g.LogItems.Count; $i++) { $keep.Add($g.LogItems[$i]) }
        $g.LogItems = $keep
        $g.C.LogList.ItemsSource = $keep
    }
    $n = $g.LogItems.Count
    if ($n -eq 1) { $g.C.LogCount.Text = '1 línea' } else { $g.C.LogCount.Text = ('{0} líneas' -f $n) }
    if ($g.LogVisible -and $n -gt 0 -and $g.C.AutoScrollChk.IsChecked) {
        $g.C.LogList.ScrollIntoView($g.LogItems[$n - 1])
        Reset-CSWGuiLogHScroll
    }
    Update-CSWGuiLogToggle
}

function Reset-CSWGuiLogHScroll {
    # ScrollIntoView desplaza en horizontal con lineas largas y oculta la hora: volver al borde izquierdo
    $g = $script:CSWGui
    try {
        if (-not $g.ContainsKey('LogScroll') -or -not $g.LogScroll) {
            $d = $g.C.LogList
            while ($d -and -not ($d -is [System.Windows.Controls.ScrollViewer])) {
                if ([System.Windows.Media.VisualTreeHelper]::GetChildrenCount($d) -lt 1) { $d = $null; break }
                $d = [System.Windows.Media.VisualTreeHelper]::GetChild($d, 0)
            }
            $g.LogScroll = $d
        }
        if ($g.LogScroll) { $g.LogScroll.ScrollToHorizontalOffset(0) }
    }
    catch { }
}

function Receive-CSWGuiLogQueue {
    param([int]$Max = 600)
    $g = $script:CSWGui
    $q = $global:CSW.LogQueue
    if ($null -eq $q) { return 0 }
    $entry = $null
    $n = 0
    while ($n -lt $Max -and $q.TryDequeue([ref]$entry)) {
        $n++
        if ($null -eq $entry) { continue }
        $msg = [string](Get-CSWGuiProp $entry 'Message')
        $lvl = [string](Get-CSWGuiProp $entry 'Level')
        $tm = Get-CSWGuiProp $entry 'Time'
        Add-CSWGuiLog -Message $msg -Level $lvl -Time $tm
    }
    if ($n -gt 0) { Update-CSWGuiLogView }
    return $n
}

function Update-CSWGuiCounter {
    $g = $script:CSWGui
    $c = 0
    if ($global:CSW.History) { $c = $global:CSW.History.Count }
    $g.C.CounterText.Text = ('Acciones en la sesión: {0}' -f $c)
}

function Set-CSWGuiBusy {
    param([bool]$Busy, [string]$Label = '')
    $g = $script:CSWGui
    $g.Busy = $Busy
    $enabled = -not $Busy
    foreach ($b in @($g.RunButtons)) { $b.IsEnabled = $enabled }
    foreach ($b in @($g.QuickTileButtons)) { $b.IsEnabled = ($enabled -and [bool]$b.Tag) }
    $g.C.QuickBtn.IsEnabled = $enabled
    $g.C.ReportBtn.IsEnabled = $enabled
    if ($Busy) {
        $g.C.StatusText.Text = ('En curso: {0}' -f $Label)
        $g.C.StatusDot.Fill = ConvertTo-CSWGuiBrush '#B45309'
        $g.C.Progress.Visibility = 'Visible'
        $g.C.Progress.IsIndeterminate = $true
        $g.C.StopBtn.Visibility = 'Visible'
        $g.C.ElapsedText.Text = '00:00'
        $g.Stopwatch.Reset(); $g.Stopwatch.Start()
    }
    else {
        $g.Stopwatch.Stop()
        $g.C.Progress.IsIndeterminate = $false
        $g.C.Progress.Visibility = 'Hidden'
        $g.C.StopBtn.Visibility = 'Collapsed'
        $g.C.StatusDot.Fill = ConvertTo-CSWGuiBrush '#15803D'
    }
}

# ---------------------------------------------------------------------------
# Mensajes propios (misma semántica que MessageBox: devuelve 'Yes', 'No', 'OK' o
# 'Cancel'; es modal respecto a la ventana propietaria). Si algo falla al construir
# el diálogo se recurre a MessageBox estándar.
# ---------------------------------------------------------------------------
function Show-CSWGuiMessage {
    param(
        $Owner,
        [string]$Text,
        [string]$Caption = 'Cybersutro win',
        [ValidateSet('OK', 'OKCancel', 'YesNo', 'YesNoCancel')][string]$Buttons = 'OK',
        [ValidateSet('Information', 'Warning', 'Danger', 'Error', 'Question')][string]$Icon = 'Information',
        [string]$Default = ''
    )
    # Equivalente a cerrar con Esc / Alt+F4 / sin elegir
    $cancelValue = 'Cancel'
    if ($Buttons -eq 'YesNo') { $cancelValue = 'No' } elseif ($Buttons -eq 'OK') { $cancelValue = 'OK' }
    try {
        $g = $script:CSWGui
        $dlg = [System.Windows.Markup.XamlReader]::Parse($script:CSWGuiMessageXaml)
        $dlg.Resources.MergedDictionaries.Add($g.Styles)
        if ($Owner -and $Owner.IsLoaded -and $Owner.IsVisible) { $dlg.Owner = $Owner } else { $dlg.WindowStartupLocation = 'CenterScreen' }
        $dlg.Title = $Caption
        $dlg.FindName('MTitle').Text = $Caption
        $dlg.FindName('MText').Text = $Text
        $glyph = 0xE946; $fg = '#0B5CAD'; $bg = '#E8F0FA'
        switch ($Icon) {
            'Warning' { $glyph = 0xE7BA; $fg = '#B45309'; $bg = '#FEF3E2' }
            'Danger' { $glyph = 0xE7BA; $fg = '#B91C1C'; $bg = '#FDECEC' }
            'Error' { $glyph = 0xE783; $fg = '#B91C1C'; $bg = '#FDECEC' }
            'Question' { $glyph = 0xE9CE; $fg = '#0B5CAD'; $bg = '#E8F0FA' }
        }
        $dlg.FindName('MIcon').Text = [string][char]$glyph
        $dlg.FindName('MIcon').Foreground = ConvertTo-CSWGuiBrush $fg
        $dlg.FindName('MIconBg').Background = ConvertTo-CSWGuiBrush $bg
        $dlg.FindName('MStripe').Background = ConvertTo-CSWGuiBrush $fg

        $yesStyle = 'BtnPrimary'
        if ($Icon -eq 'Danger') { $yesStyle = 'BtnDangerLg' }
        $spec = New-Object System.Collections.ArrayList
        switch ($Buttons) {
            'OK' { [void]$spec.Add(@('OK', 'Aceptar', 'BtnPrimary')) }
            'OKCancel' { [void]$spec.Add(@('Cancel', 'Cancelar', 'BtnSecondary')); [void]$spec.Add(@('OK', 'Aceptar', 'BtnPrimary')) }
            'YesNo' { [void]$spec.Add(@('No', 'No', 'BtnSecondary')); [void]$spec.Add(@('Yes', 'Sí', $yesStyle)) }
            'YesNoCancel' { [void]$spec.Add(@('Cancel', 'Cancelar', 'BtnSecondary')); [void]$spec.Add(@('No', 'No', 'BtnSecondary')); [void]$spec.Add(@('Yes', 'Sí', 'BtnPrimary')) }
        }
        $def = $Default
        if (-not $def) { if ($Buttons -like 'Yes*') { $def = 'Yes' } else { $def = 'OK' } }
        $panel = $dlg.FindName('MButtons')
        $focusBtn = $null
        foreach ($b in $spec) {
            $btn = New-Object System.Windows.Controls.Button
            $btn.Content = $b[1]
            $btn.Tag = $b[0]
            $btn.Style = $g.Styles[$b[2]]
            $btn.MinWidth = 96
            $btn.Margin = '8,0,0,0'
            if ($b[0] -eq $def) { $btn.IsDefault = $true; $focusBtn = $btn }
            if ($b[0] -eq $cancelValue) { $btn.IsCancel = $true }
            $btn.Add_Click({ param($s, $e) $w = [System.Windows.Window]::GetWindow($s); $w.Tag = [string]$s.Tag; $w.Close() })
            [void]$panel.Children.Add($btn)
        }
        $dlg.Add_MouseLeftButtonDown({ param($s, $e) try { $s.DragMove() } catch { } })
        if ($focusBtn) { $dlg.Add_ContentRendered({ param($s, $e) try { [void]$focusBtn.Focus() } catch { } }.GetNewClosure()) }
        [void]$dlg.ShowDialog()
        $r = [string]$dlg.Tag
        if (-not $r) { $r = $cancelValue }
        return $r
    }
    catch {
        $mbIcon = $Icon
        if ($Icon -eq 'Danger') { $mbIcon = 'Warning' }
        $mbDef = 'None'
        if ($Default) { $mbDef = $Default }
        if ($Owner) { $r = [System.Windows.MessageBox]::Show($Owner, $Text, $Caption, $Buttons, $mbIcon, $mbDef) }
        else { $r = [System.Windows.MessageBox]::Show($Text, $Caption, $Buttons, $mbIcon, $mbDef) }
        return [string]$r
    }
}

# ---------------------------------------------------------------------------
# Runspace de trabajo y tareas
# ---------------------------------------------------------------------------
function Start-CSWGuiTask {
    param([string]$Kind, [string]$Label, [string]$Script, [hashtable]$Arguments)
    $g = $script:CSWGui
    if ($g.Busy) { return $false }
    $ps = [powershell]::Create()
    $ps.Runspace = $g.Runspace
    [void]$ps.AddScript($Script)
    if ($Arguments) { foreach ($k in $Arguments.Keys) { [void]$ps.AddParameter($k, $Arguments[$k]) } }
    Set-CSWGuiBusy -Busy $true -Label $Label
    $g.Task = @{ PS = $ps; Handle = $ps.BeginInvoke(); Kind = $Kind; Label = $Label; Stopped = $false }
    return $true
}

function Complete-CSWGuiTask {
    $g = $script:CSWGui
    $t = $g.Task
    $out = @()
    $failure = $null
    try { $out = @($t.PS.EndInvoke($t.Handle)) }
    catch {
        $failure = $_.Exception
        while ($failure.InnerException -and $failure -is [System.Management.Automation.MethodInvocationException]) { $failure = $failure.InnerException }
    }
    try {
        foreach ($er in @($t.PS.Streams.Error)) { Add-CSWGuiLog -Message ([string]$er) -Level Warn }
    }
    catch { }
    try { $t.PS.Dispose() } catch { }
    $g.Task = $null
    [void](Receive-CSWGuiLogQueue -Max 100000)

    $elapsed = $g.Stopwatch.Elapsed
    $g.C.ElapsedText.Text = ('{0:00}:{1:00}' -f [Math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds)
    Set-CSWGuiBusy -Busy $false
    Update-CSWGuiCounter
    $dur = '{0:mm\:ss}' -f $elapsed

    if ($t.Stopped -or ($failure -is [System.Management.Automation.PipelineStoppedException])) {
        Add-CSWGuiLog -Message ('Acción detenida por el usuario: {0}' -f $t.Label) -Level Warn
        if ($t.Kind -ne 'Init') {
            try {
                [void]$global:CSW.History.Add([pscustomobject]@{
                        Time = (Get-Date).Add(-$elapsed); Module = ''; Action = [string]$t.Label; FullId = ''; Params = ''
                        Status = 'Warn'; Summary = 'Detenida por el técnico antes de terminar'; Duration = $dur
                    })
                Update-CSWGuiCounter
            }
            catch { }
        }
        $g.C.StatusText.Text = ('Detenida: {0} ({1})' -f $t.Label, $dur)
        Update-CSWGuiLogView
        return
    }
    if ($failure) {
        Add-CSWGuiLog -Message ('Error inesperado en {0}: {1}' -f $t.Label, $failure.Message) -Level Error
        $g.C.StatusText.Text = ('Error: {0} ({1})' -f $t.Label, $dur)
        Update-CSWGuiLogView
        if ($t.Kind -eq 'Init') { Add-CSWGuiLog -Message 'El motor de trabajo no se pudo iniciar. Reinicie la herramienta.' -Level Error }
        return
    }

    switch ($t.Kind) {
        'Init' {
            $g.Ready = $true
            $g.C.StatusText.Text = 'Listo'
            Add-CSWGuiLog -Message ('Motor de trabajo listo ({0} módulos cargados en segundo plano).' -f ($out | Select-Object -Last 1)) -Level Ok
            if ($g.AutoRunAction) { Invoke-CSWGuiRunAction -FullId $g.AutoRunAction -NoPrompt }
        }
        'Action' {
            $st = [string]($out | Select-Object -Last 1)
            if (-not $st) { $st = 'OK' }
            $g.C.StatusText.Text = ('Última: {0} - {1} ({2})' -f $t.Label, $st, $dur)
            if ($st -eq 'Error') { $g.C.StatusDot.Fill = ConvertTo-CSWGuiBrush '#B91C1C' }
            elseif ($st -eq 'Warn') { $g.C.StatusDot.Fill = ConvertTo-CSWGuiBrush '#B45309' }
        }
        'Quick' {
            $g.C.StatusText.Text = ('Reparación rápida finalizada ({0})' -f $dur)
            $path = [string]($out | Where-Object { $_ -is [string] } | Select-Object -Last 1)
            if ($path -and (Test-Path -LiteralPath $path)) {
                $r = Show-CSWGuiMessage -Owner $g.Window -Text ("Informe generado:`n{0}`n`n¿Desea abrirlo ahora?" -f $path) -Caption 'Reparación rápida finalizada' -Buttons 'YesNo' -Icon 'Information'
                if ($r -eq 'Yes') { try { Start-Process -FilePath $path } catch { } }
            }
        }
        'Report' {
            $g.C.StatusText.Text = 'Informe generado'
        }
        default { $g.C.StatusText.Text = 'Listo' }
    }
    Update-CSWGuiLogView
}

function Stop-CSWGuiTask {
    $g = $script:CSWGui
    $t = $g.Task
    if (-not $t) { return }
    $r = Show-CSWGuiMessage -Owner $g.Window -Text ("Se detendrá la acción en curso: {0}`n`nAviso: por seguridad, sfc, dism y chkdsk no se interrumpen y podrían seguir ejecutándose en segundo plano hasta terminar; el resto de procesos externos se cierran.`n`n¿Desea detenerla?" -f $t.Label) -Caption 'Detener acción' -Buttons 'YesNo' -Icon 'Warning'
    if ($r -ne 'Yes') { return }
    $t.Stopped = $true
    $g.C.StatusText.Text = ('Deteniendo: {0}…' -f $t.Label)
    Add-CSWGuiLog -Message 'Deteniendo la acción en curso...' -Level Warn
    try { [void]$t.PS.BeginStop($null, $null) } catch { }
}

# ---------------------------------------------------------------------------
# Diálogo de entradas y confirmaciones
# ---------------------------------------------------------------------------
function Show-CSWGuiInputDialog {
    param($Action)
    $g = $script:CSWGui
    $dlg = [System.Windows.Markup.XamlReader]::Parse($script:CSWGuiDialogXaml)
    $dlg.Resources.MergedDictionaries.Add($g.Styles)
    $dlg.Owner = $g.Window
    $dlg.FindName('DTitle').Text = [string]$Action.Name
    $dlg.FindName('DDesc').Text = [string]$Action.Description
    $dlg.FindName('DHeader').Add_MouseLeftButtonDown({ param($s, $e) try { ([System.Windows.Window]::GetWindow($s)).DragMove() } catch { } })
    $fields = $dlg.FindName('Fields')
    $rows = New-Object System.Collections.ArrayList
    $first = $null

    foreach ($in in @($Action.Inputs)) {
        if ($null -eq $in) { continue }
        $name = [string](Get-CSWGuiProp $in 'Name')
        if (-not $name) { continue }
        $label = [string](Get-CSWGuiProp $in 'Label')
        if (-not $label) { $label = $name }
        $type = [string](Get-CSWGuiProp $in 'Type')
        $def = Get-CSWGuiProp $in 'Default'
        $ctl = $null; $kind = 'Text'

        if ($type -eq 'Bool') {
            $kind = 'Bool'
            $ctl = New-Object System.Windows.Controls.CheckBox
            $ctl.Content = $label
            $ctl.Margin = '0,14,0,2'
            $isOn = $false
            if ($def -is [bool]) { $isOn = $def }
            elseif ($null -ne $def) { $isOn = ([string]$def -match '^(true|1|si|yes|s|y)$') }
            $ctl.IsChecked = $isOn
            [void]$fields.Children.Add($ctl)
        }
        else {
            $lbl = New-Object System.Windows.Controls.TextBlock
            $lbl.Text = $label
            $lbl.TextWrapping = 'Wrap'
            $lbl.Style = $g.Styles['FieldLabel']
            [void]$fields.Children.Add($lbl)
            if ($type -eq 'Choice') {
                $kind = 'Choice'
                $ctl = New-Object System.Windows.Controls.ComboBox
                foreach ($c in @(Get-CSWGuiProp $in 'Choices')) { if ($null -ne $c) { [void]$ctl.Items.Add([string]$c) } }
                if ($null -ne $def -and $ctl.Items.Contains([string]$def)) { $ctl.SelectedItem = [string]$def }
                elseif ($ctl.Items.Count -gt 0) { $ctl.SelectedIndex = 0 }
            }
            elseif ($name -match 'Password') {
                $kind = 'Password'
                $ctl = New-Object System.Windows.Controls.PasswordBox
                if ($null -ne $def) { $ctl.Password = [string]$def }
            }
            else {
                $ctl = New-Object System.Windows.Controls.TextBox
                if ($null -ne $def) { $ctl.Text = [string]$def }
            }
            [void]$fields.Children.Add($ctl)
        }
        if (-not $first) { $first = $ctl }
        [void]$rows.Add(@{ Name = $name; Kind = $kind; Control = $ctl; Default = $def })
    }

    $dlg.FindName('DOk').Add_Click({ param($s, $e) ([System.Windows.Window]::GetWindow($s)).DialogResult = $true })
    if ($first) { $dlg.Add_ContentRendered({ param($s, $e) try { [void]$first.Focus(); if ($first -is [System.Windows.Controls.TextBox]) { $first.SelectAll() } } catch { } }.GetNewClosure()) }

    $res = $dlg.ShowDialog()
    if (-not $res) { return $null }

    $params = @{}
    foreach ($r in $rows) {
        $val = $null
        switch ($r.Kind) {
            'Bool' { $val = [bool]$r.Control.IsChecked }
            'Choice' { $val = [string]$r.Control.SelectedItem }
            'Password' { $val = $r.Control.Password }
            default { $val = $r.Control.Text }
        }
        if ($r.Kind -ne 'Bool') {
            if ($null -eq $val -or [string]$val -eq '') { continue }   # vacío: usa el valor por defecto de la función
            $defIsNum = ($r.Default -is [int] -or $r.Default -is [long] -or ([string]$r.Default -match '^-?\d+$'))
            if ($r.Kind -eq 'Text' -and $defIsNum -and ([string]$val).Trim() -match '^-?\d{1,9}$') { $val = [int]([string]$val).Trim() }
        }
        $params[$r.Name] = $val
    }
    return $params
}

function Confirm-CSWGuiAction {
    param($Action)
    $g = $script:CSWGui
    $risk = [string]$Action.Risk
    $lines = New-Object System.Collections.ArrayList
    if ($risk -eq 'Medium' -or $risk -eq 'High') {
        $msg = [string]$Action.ConfirmMessage
        if (-not $msg) { $msg = "La acción '$($Action.Name)' realizará cambios en el sistema." }
        [void]$lines.Add($msg)
        if ($Action.ModifiesSystem) {
            [void]$lines.Add('')
            if ($global:CSW.RestorePointDone) { [void]$lines.Add('Ya existe un punto de restauración creado en esta sesión.') }
            else { [void]$lines.Add('Se creará un punto de restauración antes.') }
        }
        if ($Action.LongRunning) { [void]$lines.Add(''); [void]$lines.Add('Esta acción puede tardar varios minutos.') }
        [void]$lines.Add(''); [void]$lines.Add('¿Desea continuar?')
        $cap = 'Confirmar acción · riesgo medio'
        $ico = 'Warning'
        if ($risk -eq 'High') { $cap = 'Confirmar acción · RIESGO ALTO'; $ico = 'Danger' }
        $r = Show-CSWGuiMessage -Owner $g.Window -Text ($lines -join "`n") -Caption $cap -Buttons 'YesNo' -Icon $ico -Default 'No'
        return ($r -eq 'Yes')
    }
    if ($Action.LongRunning) {
        $r = Show-CSWGuiMessage -Owner $g.Window -Text ("'{0}' puede tardar varios minutos. Podrá seguir el progreso en el registro.`n`n¿Desea continuar?" -f $Action.Name) -Caption 'Acción de larga duración' -Buttons 'OKCancel' -Icon 'Information'
        return ($r -eq 'OK')
    }
    return $true
}

function Invoke-CSWGuiRunAction {
    param([string]$FullId, [switch]$NoPrompt)
    $g = $script:CSWGui
    if ($g.Busy) { return }
    if (-not $g.Ready) { Add-CSWGuiLog -Message 'El motor de trabajo aún no está listo.' -Level Warn; Update-CSWGuiLogView; return }
    $a = $null
    if ($g.ActionIndex.ContainsKey($FullId)) { $a = $g.ActionIndex[$FullId] }
    if (-not $a) { Add-CSWGuiLog -Message "Acción no encontrada: $FullId" -Level Error; Update-CSWGuiLogView; return }
    $params = @{}
    if (-not $NoPrompt) {
        $inputs = @(@($a.Inputs) | Where-Object { $null -ne $_ })
        if ($inputs.Count -gt 0) {
            $params = Show-CSWGuiInputDialog -Action $a
            if ($null -eq $params) { return }
        }
        if (-not (Confirm-CSWGuiAction -Action $a)) { return }
    }
    [void](Start-CSWGuiTask -Kind 'Action' -Label ([string]$a.Name) -Script $script:CSWGuiActionScript -Arguments @{ FullId = $FullId; Params = $params })
}

function Invoke-CSWGuiQuickRepair {
    $g = $script:CSWGui
    if ($g.Busy -or -not $g.Ready) { return }
    $names = @()
    $i = 0
    foreach ($id in @(Get-CSWQuickRepairSteps)) {
        $i++
        $n = $id
        if ($g.ActionIndex.ContainsKey($id)) { $n = [string]$g.ActionIndex[$id].Name } else { $n = "$id (no disponible, se omitirá)" }
        $names += ('  {0}. {1}' -f $i, $n)
    }
    $msg = "Se ejecutará la reparación rápida:`n`n{0}`n`nSe creará un punto de restauración antes. El proceso puede tardar entre 15 y 60 minutos y al final se generará el informe HTML.`n`n¿Desea continuar?" -f ($names -join "`n")
    $r = Show-CSWGuiMessage -Owner $g.Window -Text $msg -Caption 'Reparación rápida' -Buttons 'YesNo' -Icon 'Warning' -Default 'No'
    if ($r -ne 'Yes') { return }
    [void](Start-CSWGuiTask -Kind 'Quick' -Label 'Reparación rápida' -Script $script:CSWGuiQuickScript)
}

# ---------------------------------------------------------------------------
# Inicio (panel)
# ---------------------------------------------------------------------------
function New-CSWGuiKpi {
    param([int]$Glyph, [string]$Label)
    $el = [System.Windows.Markup.XamlReader]::Parse($script:CSWGuiKpiXaml)
    $k = @{ Root = $el }
    foreach ($n in 'KIconBg', 'KIcon', 'KLabel', 'KValue', 'KSub', 'KBar', 'KFill') { $k[$n] = $el.FindName($n) }
    $k.KIcon.Text = [string][char]$Glyph
    $k.KLabel.Text = $Label
    return $k
}

function Set-CSWGuiKpi {
    param($Kpi, [string]$Value, [string]$Sub, $Percent = $null, [string]$Color = '#0B5CAD', [string]$ValueColor = '#0F172A')
    $Kpi.KValue.Text = $Value
    $Kpi.KValue.Foreground = ConvertTo-CSWGuiBrush $ValueColor
    $Kpi.KSub.Text = $Sub
    $Kpi.KSub.ToolTip = $Sub
    if ($null -eq $Percent) { $Kpi.KBar.Visibility = 'Hidden'; return }
    $p = [double]$Percent
    if ($p -lt 0) { $p = 0 } elseif ($p -gt 100) { $p = 100 }
    $Kpi.KBar.ColumnDefinitions[0].Width = New-Object System.Windows.GridLength($p, ([System.Windows.GridUnitType]::Star))
    $Kpi.KBar.ColumnDefinitions[1].Width = New-Object System.Windows.GridLength((100 - $p), ([System.Windows.GridUnitType]::Star))
    $Kpi.KFill.Background = ConvertTo-CSWGuiBrush $Color
    $Kpi.KBar.Visibility = 'Visible'
}

function Get-CSWGuiLevelColor {
    # Azul corporativo normal; ámbar y rojo al superar los umbrales
    param([double]$Value, [double]$Warn, [double]$Crit)
    if ($Value -ge $Crit) { return '#B91C1C' }
    if ($Value -ge $Warn) { return '#B45309' }
    return '#0B5CAD'
}

function Update-CSWGuiKpis {
    param($Data)
    $g = $script:CSWGui
    $k = $g.Kpi
    if (-not $k) { return }
    $ci = [System.Globalization.CultureInfo]::CurrentCulture
    $get = { param($n) if ($null -ne $Data -and $Data -is [System.Collections.IDictionary] -and $Data.Contains($n)) { return $Data[$n] } return $null }

    # Procesador
    $name = [string](& $get 'CpuName')
    if ($name) {
        $name = $name -replace '\((R|TM)\)', '' -replace '(?i)\s+CPU\b', '' -replace '\s*@.*$', '' -replace '(?i)\s+(\d+|Six|Quad|Eight|Dual|Twelve|Sixteen)-Core Processor', '' -replace '(?i)\s+Processor$', '' -replace '\s{2,}', ' '
        $name = $name.Trim()
    }
    $cores = & $get 'CpuCores'; $thr = & $get 'CpuThreads'; $load = & $get 'CpuLoad'
    $sub = $name
    if ($cores) { $sub = ('{0} · {1} núcleos' -f $name, $cores).Trim(' ', '·') }
    $k.Cpu.Root.ToolTip = ('{0}{1}{2} núcleos / {3} hilos' -f [string](& $get 'CpuName'), [Environment]::NewLine, $cores, $thr)
    if (-not $sub) { $sub = 'Sin datos del procesador' }
    if ($null -ne $load) { Set-CSWGuiKpi -Kpi $k.Cpu -Value ('{0} % de uso' -f $load) -Sub $sub -Percent $load -Color (Get-CSWGuiLevelColor $load 70 90) }
    else { Set-CSWGuiKpi -Kpi $k.Cpu -Value '—' -Sub $sub }

    # Memoria
    $tot = & $get 'RamTotalKB'; $free = & $get 'RamFreeKB'
    if ($tot -and $null -ne $free) {
        $usedPct = [Math]::Round((($tot - $free) / $tot) * 100)
        $totGb = $tot / 1MB; $usedGb = ($tot - $free) / 1MB
        Set-CSWGuiKpi -Kpi $k.Ram -Value ([string]::Format($ci, '{0:N1} GB', $totGb)) -Sub ([string]::Format($ci, '{0:N0} % en uso ({1:N1} GB)', $usedPct, $usedGb)) -Percent $usedPct -Color (Get-CSWGuiLevelColor $usedPct 75 90)
    }
    else { Set-CSWGuiKpi -Kpi $k.Ram -Value '—' -Sub 'Sin datos de memoria' }

    # Disco del sistema
    $size = & $get 'DiskSize'; $dfree = & $get 'DiskFree'; $did = [string](& $get 'DiskId')
    if (-not $did) { $did = 'C:' }
    $k.Disk.KLabel.Text = ('Disco {0}' -f $did)
    if ($size -and $null -ne $dfree) {
        $usedPct = [Math]::Round((($size - $dfree) / $size) * 100)
        $freePct = 100 - $usedPct
        $col = '#15803D'
        if ($freePct -lt 10) { $col = '#B91C1C' } elseif ($freePct -lt 20) { $col = '#B45309' }
        $vcol = '#0F172A'
        if ($freePct -lt 10) { $vcol = '#B91C1C' }
        Set-CSWGuiKpi -Kpi $k.Disk -Value ([string]::Format($ci, '{0:N0} GB libres', ($dfree / 1GB))) -Sub ([string]::Format($ci, 'de {0:N0} GB · {1:N0} % ocupado', ($size / 1GB), $usedPct)) -Percent $usedPct -Color $col -ValueColor $vcol
    }
    else { Set-CSWGuiKpi -Kpi $k.Disk -Value '—' -Sub 'Sin datos del disco' }

    # Tiempo encendido
    $ticks = & $get 'BootTicks'
    if ($ticks) {
        $boot = New-Object DateTime([long]$ticks)
        $up = (Get-Date) - $boot
        if ($up.TotalDays -ge 1) { $val = '{0} d {1} h' -f [Math]::Floor($up.TotalDays), $up.Hours }
        elseif ($up.TotalHours -ge 1) { $val = '{0} h {1} min' -f [Math]::Floor($up.TotalHours), $up.Minutes }
        else { $val = '{0} min' -f [Math]::Max(0, [Math]::Floor($up.TotalMinutes)) }
        $since = $boot.ToString('dd/MM HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
        if ($up.TotalDays -ge 7) { Set-CSWGuiKpi -Kpi $k.Up -Value $val -Sub ('Conviene reiniciar · desde {0}' -f $since) -ValueColor '#B45309' }
        else { Set-CSWGuiKpi -Kpi $k.Up -Value $val -Sub ('Desde el {0}' -f $since) }
    }
    else { Set-CSWGuiKpi -Kpi $k.Up -Value '—' -Sub 'Sin datos de arranque' }
}

function Set-CSWGuiKpisLoading {
    $g = $script:CSWGui
    if (-not $g.Kpi) { return }
    foreach ($n in 'Cpu', 'Ram', 'Disk', 'Up') {
        $x = $g.Kpi[$n]
        $x.KValue.Text = '—'; $x.KValue.Foreground = ConvertTo-CSWGuiBrush '#94A3B8'
        $x.KSub.Text = 'Cargando…'; $x.KBar.Visibility = 'Hidden'
    }
}

function Start-CSWGuiSummaryLoad {
    $g = $script:CSWGui
    if ($g.SummaryPS) { return }
    $g.C.SummaryGrid.Children.Clear()
    $g.C.SummaryGrid.RowDefinitions.Clear()
    $g.C.SummaryLoading.Text = 'Cargando información del equipo…'
    $g.C.SummaryLoading.Visibility = 'Visible'
    Set-CSWGuiKpisLoading
    $ps = [powershell]::Create()
    [void]$ps.AddScript($script:CSWGuiSummaryScript).AddParameter('CorePath', $g.CorePath)
    $g.SummaryPS = $ps
    $g.SummaryHandle = $ps.BeginInvoke()
}

function Complete-CSWGuiSummaryLoad {
    $g = $script:CSWGui
    $ps = $g.SummaryPS
    $rows = @()
    try { $rows = @($ps.EndInvoke($g.SummaryHandle)) } catch { }
    try { $ps.Dispose() } catch { }
    $g.SummaryPS = $null
    $kpiRow = $null
    foreach ($r in $rows) { if ($r -and [string]$r.K -eq '__kpi') { $kpiRow = $r } }
    $rows = @($rows | Where-Object { $_ -and [string]$_.K -ne '__kpi' })
    $kd = $null
    if ($kpiRow) { $kd = $kpiRow.Kpi }
    try { Update-CSWGuiKpis -Data $kd } catch { Add-CSWGuiLog -Message ("No se pudieron mostrar los indicadores: {0}" -f $_.Exception.Message) -Level Warn }

    $grid = $g.C.SummaryGrid
    $grid.Children.Clear(); $grid.RowDefinitions.Clear()
    if ($rows.Count -eq 0) { $g.C.SummaryLoading.Text = 'No se pudo obtener el resumen del equipo.'; return }
    $g.C.SummaryLoading.Visibility = 'Collapsed'
    $display = @{ 'Ultimo arranque' = 'Último arranque'; 'N/S' = 'Número de serie' }
    $line = ConvertTo-CSWGuiBrush '#EEF2F6'
    $i = 0
    foreach ($r in $rows) {
        $rd = New-Object System.Windows.Controls.RowDefinition
        $rd.Height = 'Auto'
        $grid.RowDefinitions.Add($rd)
        $key = [string]$r.K
        if ($display.ContainsKey($key)) { $key = $display[$key] }
        $sep = New-Object System.Windows.Controls.Border
        $sep.BorderBrush = $line
        if ($i -lt $rows.Count - 1) { $sep.BorderThickness = '0,0,0,1' }
        [System.Windows.Controls.Grid]::SetColumnSpan($sep, 2)
        $k = New-Object System.Windows.Controls.TextBlock
        $k.Text = $key; $k.Foreground = $g.B.Muted; $k.Margin = '0,6,10,6'; $k.FontSize = 12.5; $k.TextTrimming = 'CharacterEllipsis'
        $v = New-Object System.Windows.Controls.TextBlock
        $v.Text = [string]$r.V; $v.TextWrapping = 'Wrap'; $v.Margin = '0,6,0,6'; $v.Foreground = $g.B.Ink
        [System.Windows.Controls.Grid]::SetRow($sep, $i); [System.Windows.Controls.Grid]::SetRow($k, $i); [System.Windows.Controls.Grid]::SetRow($v, $i)
        [System.Windows.Controls.Grid]::SetColumn($v, 1)
        [void]$grid.Children.Add($sep); [void]$grid.Children.Add($k); [void]$grid.Children.Add($v)
        $i++
    }
}

function New-CSWGuiTile {
    param([int]$Glyph, [string]$Title, [string]$Sub, [string]$Fg = '#0B5CAD', [string]$Bg = '#E8F0FA')
    $btn = [System.Windows.Markup.XamlReader]::Parse($script:CSWGuiTileXaml)
    $btn.FindName('TIcon').Text = [string][char]$Glyph
    $btn.FindName('TIcon').Foreground = ConvertTo-CSWGuiBrush $Fg
    $btn.FindName('TIconBg').Background = ConvertTo-CSWGuiBrush $Bg
    $btn.FindName('TTitle').Text = $Title
    $btn.FindName('TSub').Text = $Sub
    return $btn
}

function Update-CSWGuiDashLayout {
    # Columnas adaptativas según el ancho disponible (1366x768 ... 1920x1080 y más)
    $g = $script:CSWGui
    $w = $g.C.DashView.ActualWidth - 56
    if ($w -le 0) { return }
    if ($w -ge 960) { $g.C.KpiGrid.Columns = 5 } else { $g.C.KpiGrid.Columns = 3 }
    if ($w -ge 960) { $g.C.QuickTiles.Columns = 4 } else { $g.C.QuickTiles.Columns = 2 }
    if ($w -ge 1280) { $g.C.ModuleTiles.Columns = 5 } elseif ($w -ge 900) { $g.C.ModuleTiles.Columns = 4 } else { $g.C.ModuleTiles.Columns = 3 }
}

function Initialize-CSWGuiDashboard {
    $g = $script:CSWGui
    $ci = New-Object System.Globalization.CultureInfo('es-ES')
    $d = (Get-Date).ToString('dddd, d \de MMMM \de yyyy', $ci)
    $g.C.DateText.Text = $d.Substring(0, 1).ToUpper($ci) + $d.Substring(1)

    # Indicadores
    $g.Kpi = @{
        Cpu  = (New-CSWGuiKpi -Glyph 0xE950 -Label 'Procesador')
        Ram  = (New-CSWGuiKpi -Glyph 0xE964 -Label 'Memoria RAM')
        Disk = (New-CSWGuiKpi -Glyph 0xEDA2 -Label 'Disco C:')
        Up   = (New-CSWGuiKpi -Glyph 0xE823 -Label 'Tiempo encendido')
        Adm  = (New-CSWGuiKpi -Glyph 0xE7EF -Label 'Privilegios')
    }
    foreach ($n in 'Cpu', 'Ram', 'Disk', 'Up', 'Adm') { [void]$g.C.KpiGrid.Children.Add($g.Kpi[$n].Root) }
    if ($g.IsAdmin) {
        Set-CSWGuiKpi -Kpi $g.Kpi.Adm -Value 'Administrador' -Sub 'Todas las acciones disponibles' -ValueColor '#15803D'
    }
    else {
        Set-CSWGuiKpi -Kpi $g.Kpi.Adm -Value 'Limitado' -Sub 'Muchas acciones fallarán' -ValueColor '#B91C1C'
        $g.Kpi.Adm.KIcon.Text = [string][char]0xE7BA
        $g.Kpi.Adm.KIcon.Foreground = ConvertTo-CSWGuiBrush '#B91C1C'
        $g.Kpi.Adm.KIconBg.Background = ConvertTo-CSWGuiBrush '#FDECEC'
    }

    # Pasos de la reparación rápida
    $i = 0
    foreach ($id in @(Get-CSWQuickRepairSteps)) {
        $i++
        $name = $id; $ok = $false
        $a = $null
        try { $a = Get-CSWAction -FullId $id } catch { }
        if ($a) { $name = [string]$a.Name; $ok = $true }
        $chip = New-Object System.Windows.Controls.Border
        $chip.CornerRadius = '14'; $chip.Padding = '4,4,12,4'; $chip.Margin = '0,0,8,8'
        $chip.Background = ConvertTo-CSWGuiBrush '#1FFFFFFF'
        $chip.BorderBrush = ConvertTo-CSWGuiBrush '#33FFFFFF'; $chip.BorderThickness = '1'
        $sp = New-Object System.Windows.Controls.StackPanel
        $sp.Orientation = 'Horizontal'
        $num = New-Object System.Windows.Controls.Border
        $num.Width = 20; $num.Height = 20; $num.CornerRadius = '10'; $num.Background = ConvertTo-CSWGuiBrush '#FFFFFF'
        $nt = New-Object System.Windows.Controls.TextBlock
        $nt.Text = [string]$i; $nt.FontSize = 11; $nt.FontWeight = 'Bold'; $nt.Foreground = ConvertTo-CSWGuiBrush '#0B5CAD'
        $nt.HorizontalAlignment = 'Center'; $nt.VerticalAlignment = 'Center'
        $num.Child = $nt
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = $name; $t.Margin = '8,0,0,0'; $t.VerticalAlignment = 'Center'; $t.Foreground = ConvertTo-CSWGuiBrush '#FFFFFF'
        if (-not $ok) { $t.Text = "$id (no disponible)"; $t.Opacity = 0.6 }
        [void]$sp.Children.Add($num); [void]$sp.Children.Add($t)
        $chip.Child = $sp
        $chip.ToolTip = $id
        [void]$g.C.QuickSteps.Children.Add($chip)
    }

    # Accesos rápidos: disparan la acción con Invoke-CSWGuiRunAction (mismo flujo que las tarjetas)
    foreach ($q in $script:CSWGuiQuickActions) {
        $btn = New-CSWGuiTile -Glyph $q.Glyph -Title $q.Title -Sub $q.Sub -Fg $q.Fg -Bg $q.Bg
        $avail = $g.ActionIndex.ContainsKey($q.Id)
        if ($avail) {
            $btn.Tag = [string]$q.Id
            $btn.ToolTip = ('{0}{1}{1}{2}' -f [string]$g.ActionIndex[$q.Id].Description, [Environment]::NewLine, $q.Id)
        }
        else {
            $btn.Tag = ''
            $btn.IsEnabled = $false
            $btn.FindName('TSub').Text = 'No disponible (módulo no cargado)'
        }
        $btn.Add_Click({ param($s, $e) if ([string]$s.Tag) { Invoke-CSWGuiRunAction -FullId ([string]$s.Tag) } })
        [void]$g.QuickTileButtons.Add($btn)
        [void]$g.C.QuickTiles.Children.Add($btn)
    }

    # Campos del servicio
    $g.C.TechBox.Text = [string]$global:CSW.TechName
    $g.C.ClientBox.Text = [string]$global:CSW.ClientName
    $g.C.NotesBox.Text = [string]$global:CSW.Notes
    $g.C.TechBox.Add_TextChanged({ param($s, $e) $global:CSW.TechName = $s.Text })
    $g.C.ClientBox.Add_TextChanged({ param($s, $e) $global:CSW.ClientName = $s.Text })
    $g.C.NotesBox.Add_TextChanged({ param($s, $e) $global:CSW.Notes = $s.Text })

    # Accesos a módulos
    foreach ($m in $g.Modules) {
        $cnt = @($m.Actions).Count
        $sub = ('{0} acciones' -f $cnt)
        if ($cnt -eq 1) { $sub = '1 acción' }
        $btn = New-CSWGuiTile -Glyph ([int][char](Get-CSWGuiGlyph ("{0} {1}" -f $m.Icon, $m.Id))) -Title ([string]$m.Name) -Sub $sub
        $btn.Tag = [string]$m.Id
        $btn.ToolTip = [string]$m.Description
        $btn.Add_Click({ param($s, $e) Select-CSWGuiNav -Tag ([string]$s.Tag) })
        [void]$g.C.ModuleTiles.Children.Add($btn)
    }
    if ($g.Modules.Count -eq 0) {
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = 'No hay módulos cargados. Copie los archivos .psm1 en la carpeta modules.'
        $t.Foreground = $g.B.Muted
        [void]$g.C.ModuleTiles.Children.Add($t)
    }
}

# ---------------------------------------------------------------------------
# Navegación y vista de módulo
# ---------------------------------------------------------------------------
function New-CSWGuiNavItem {
    param([string]$Tag, [string]$Text, [string]$Glyph, [string]$ToolTip, [int]$Count = -1)
    $g = $script:CSWGui
    $item = New-Object System.Windows.Controls.ListBoxItem
    $item.Tag = $Tag
    $grid = New-Object System.Windows.Controls.Grid
    foreach ($w in 'Auto', '*', 'Auto') {
        $cd = New-Object System.Windows.Controls.ColumnDefinition
        $cd.Width = $w
        $grid.ColumnDefinitions.Add($cd)
    }
    $gl = New-Object System.Windows.Controls.TextBlock
    $gl.Text = $Glyph; $gl.FontFamily = $g.IconFont; $gl.FontSize = 15; $gl.Width = 28; $gl.VerticalAlignment = 'Center'
    $tx = New-Object System.Windows.Controls.TextBlock
    $tx.Text = $Text; $tx.VerticalAlignment = 'Center'; $tx.TextTrimming = 'CharacterEllipsis'
    [System.Windows.Controls.Grid]::SetColumn($tx, 1)
    [void]$grid.Children.Add($gl); [void]$grid.Children.Add($tx)
    if ($Count -ge 0) {
        $pill = New-Object System.Windows.Controls.Border
        $pill.Style = $g.Styles['NavPill']
        $pill.Margin = '6,0,0,0'
        $pt = New-Object System.Windows.Controls.TextBlock
        $pt.Text = [string]$Count; $pt.FontSize = 10.5; $pt.FontWeight = 'SemiBold'; $pt.Foreground = ConvertTo-CSWGuiBrush '#64748B'
        $pt.HorizontalAlignment = 'Center'
        $pill.Child = $pt
        [System.Windows.Controls.Grid]::SetColumn($pill, 2)
        [void]$grid.Children.Add($pill)
    }
    $item.Content = $grid
    if ($ToolTip) { $item.ToolTip = $ToolTip }
    return $item
}

function New-CSWGuiNavHeader {
    param([string]$Text)
    $g = $script:CSWGui
    $h = New-Object System.Windows.Controls.ListBoxItem
    $h.Style = $g.Styles['NavHeader']
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = $Text; $t.FontSize = 10.5; $t.FontWeight = 'SemiBold'; $t.Foreground = ConvertTo-CSWGuiBrush '#94A3B8'
    $h.Content = $t
    return $h
}

function Select-CSWGuiNav {
    param([string]$Tag)
    $g = $script:CSWGui
    foreach ($it in $g.C.NavList.Items) {
        if ($it.Tag -eq $Tag) { $g.C.NavList.SelectedItem = $it; return }
    }
}

function New-CSWGuiFlag {
    param([string]$Glyph, [string]$Text, [string]$Fg, [string]$Bg)
    $g = $script:CSWGui
    $b = New-Object System.Windows.Controls.Border
    $b.CornerRadius = '4'; $b.Padding = '6,2,7,2'; $b.Margin = '0,4,5,0'
    $b.Background = ConvertTo-CSWGuiBrush $Bg
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'
    $gl = New-Object System.Windows.Controls.TextBlock
    $gl.Text = $Glyph; $gl.FontFamily = $g.IconFont; $gl.FontSize = 10; $gl.VerticalAlignment = 'Center'
    $gl.Foreground = ConvertTo-CSWGuiBrush $Fg
    $tx = New-Object System.Windows.Controls.TextBlock
    $tx.Text = $Text; $tx.FontSize = 10.5; $tx.Margin = '5,0,0,0'; $tx.VerticalAlignment = 'Center'
    $tx.Foreground = ConvertTo-CSWGuiBrush $Fg
    [void]$sp.Children.Add($gl); [void]$sp.Children.Add($tx)
    $b.Child = $sp
    return $b
}

function New-CSWGuiActionCard {
    param($Action, [string]$Glyph)
    $g = $script:CSWGui
    $card = [System.Windows.Markup.XamlReader]::Parse($script:CSWGuiCardXaml)
    $tn = $card.FindName('TName')
    $tn.Text = [string]$Action.Name
    $tn.ToolTip = [string]$Action.Name
    $desc = [string]$Action.Description
    if (-not $desc) { $desc = 'Sin descripción.' }
    $td = $card.FindName('TDesc')
    $td.Text = $desc
    $td.ToolTip = ('{0}{1}{1}{2}  ·  {3}' -f $desc, [Environment]::NewLine, $Action.FullId, $Action.Command)
    if ($Glyph) { $card.FindName('TIcon').Text = $Glyph }
    if ($g.CardWidth) { $card.Width = $g.CardWidth }

    $risk = [string]$Action.Risk
    $badge = $card.FindName('Badge'); $bt = $card.FindName('TBadge'); $dot = $card.FindName('BDot')
    switch ($risk) {
        'High' { $bt.Text = 'Riesgo alto'; $fg = '#B91C1C'; $bg = '#FDECEC' }
        'Medium' { $bt.Text = 'Riesgo medio'; $fg = '#B45309'; $bg = '#FEF3E2' }
        default { $bt.Text = 'Riesgo bajo'; $fg = '#15803D'; $bg = '#E8F5EC' }
    }
    $bt.Foreground = ConvertTo-CSWGuiBrush $fg
    $dot.Fill = ConvertTo-CSWGuiBrush $fg
    $badge.Background = ConvertTo-CSWGuiBrush $bg

    $flags = $card.FindName('Flags')
    if ($Action.ModifiesSystem) { [void]$flags.Children.Add((New-CSWGuiFlag -Glyph ([string][char]0xE7BA) -Text 'Modifica el sistema' -Fg '#9A3412' -Bg '#FFF1E6')) }
    if ($Action.LongRunning) { [void]$flags.Children.Add((New-CSWGuiFlag -Glyph ([string][char]0xE916) -Text 'Larga duración' -Fg '#1E40AF' -Bg '#EAF1FD')) }
    if (@(@($Action.Inputs) | Where-Object { $null -ne $_ }).Count -gt 0) { [void]$flags.Children.Add((New-CSWGuiFlag -Glyph ([string][char]0xE70F) -Text 'Pide datos' -Fg '#334155' -Bg '#F1F5F9')) }

    $btn = $card.FindName('BRun')
    $btn.Tag = [string]$Action.FullId
    $btn.ToolTip = ('Ejecutar: {0}' -f $Action.Name)
    $btn.IsEnabled = (-not $g.Busy)
    $btn.Add_Click({ param($s, $e) Invoke-CSWGuiRunAction -FullId ([string]$s.Tag) })
    [void]$g.RunButtons.Add($btn)

    $search = ('{0} {1} {2}' -f $Action.Name, $Action.Description, $Action.Id).ToLowerInvariant()
    return @{ Element = $card; Search = $search }
}

function Show-CSWGuiModule {
    param([string]$ModuleId)
    $g = $script:CSWGui
    $m = $null
    foreach ($x in $g.Modules) { if ($x.Id -eq $ModuleId) { $m = $x; break } }
    if (-not $m) { return }
    $g.CurrentModule = $ModuleId
    $g.C.DashView.Visibility = 'Collapsed'
    $g.C.ModuleView.Visibility = 'Visible'
    $g.C.ModTitle.Text = [string]$m.Name
    $g.C.ModDesc.Text = [string]$m.Description
    $glyph = Get-CSWGuiGlyph ("{0} {1}" -f $m.Icon, $m.Id)
    $g.C.ModGlyph.Text = $glyph

    $acts = @(@($m.Actions) | Where-Object { $null -ne $_ })
    $nMod = @($acts | Where-Object { $_.ModifiesSystem }).Count
    $nRisk = @($acts | Where-Object { $_.Risk -eq 'Medium' -or $_.Risk -eq 'High' }).Count
    $nLong = @($acts | Where-Object { $_.LongRunning }).Count
    $meta = @(('{0} acciones' -f $acts.Count))
    if ($nRisk) { $meta += ('{0} con riesgo medio o alto' -f $nRisk) }
    if ($nMod) { $meta += ('{0} modifican el sistema' -f $nMod) }
    if ($nLong) { $meta += ('{0} de larga duración' -f $nLong) }
    $g.C.ModMeta.Text = ($meta -join '  ·  ')

    $g.C.CardsPanel.Children.Clear()
    $g.RunButtons.Clear()
    $g.Cards = New-Object System.Collections.ArrayList
    foreach ($a in @($m.Actions)) {
        if ($null -eq $a) { continue }
        try {
            $c = New-CSWGuiActionCard -Action $a -Glyph $glyph
            [void]$g.Cards.Add($c)
            [void]$g.C.CardsPanel.Children.Add($c.Element)
        }
        catch { Add-CSWGuiLog -Message ("No se pudo mostrar la acción {0}: {1}" -f $a.FullId, $_.Exception.Message) -Level Warn }
    }
    $g.C.SearchBox.Text = ''
    Update-CSWGuiFilter
    Update-CSWGuiCardWidth
    $g.C.CardsScroll.ScrollToTop()
    Invoke-CSWGuiFade -Element $g.C.ModuleView
}

function Update-CSWGuiCardWidth {
    $g = $script:CSWGui
    $avail = $g.C.CardsScroll.ViewportWidth
    if (-not $avail -or $avail -le 0) { $avail = $g.C.CardsScroll.ActualWidth - 18 }
    if ($avail -le 0) { return }
    $avail = $avail - 2
    $cols = [Math]::Max(1, [Math]::Floor($avail / 330))
    $w = [Math]::Floor($avail / $cols) - 14 - 1
    if ($w -lt 260) { $w = 260 }
    $g.CardWidth = $w
    foreach ($c in $g.Cards) { $c.Element.Width = $w }
}

function Show-CSWGuiDashboard {
    $g = $script:CSWGui
    $g.CurrentModule = $null
    $g.C.ModuleView.Visibility = 'Collapsed'
    $g.C.DashView.Visibility = 'Visible'
    $g.RunButtons.Clear()
    $g.C.CardsPanel.Children.Clear()
    Invoke-CSWGuiFade -Element $g.C.DashView
}

function Update-CSWGuiFilter {
    $g = $script:CSWGui
    $raw = ([string]$g.C.SearchBox.Text).Trim()
    $q = $raw.ToLowerInvariant()
    if ($q) { $g.C.SearchHint.Visibility = 'Collapsed'; $g.C.SearchClearBtn.Visibility = 'Visible' }
    else { $g.C.SearchHint.Visibility = 'Visible'; $g.C.SearchClearBtn.Visibility = 'Collapsed' }
    $vis = 0
    foreach ($c in $g.Cards) {
        if (-not $q -or $c.Search.Contains($q)) { $c.Element.Visibility = 'Visible'; $vis++ }
        else { $c.Element.Visibility = 'Collapsed' }
    }
    if ($vis -eq 0 -and $g.Cards.Count -gt 0) {
        $g.C.NoResultsText.Text = ('Ninguna acción de este módulo coincide con «{0}». Pruebe con otra palabra o borre la búsqueda.' -f $raw)
        $g.C.NoResults.Visibility = 'Visible'
    }
    else { $g.C.NoResults.Visibility = 'Collapsed' }
    if ($q) { $g.C.ModCount.Text = ('{0} de {1} acciones' -f $vis, $g.Cards.Count) }
    else { $g.C.ModCount.Text = ('{0} acciones' -f $g.Cards.Count) }
}

# ---------------------------------------------------------------------------
# Captura (para pruebas)
# ---------------------------------------------------------------------------
function Save-CSWGuiScreenshot {
    param([string]$Path)
    $g = $script:CSWGui
    $w = $g.Window
    $el = $w.Content
    $wd = [int][Math]::Ceiling($el.ActualWidth); $ht = [int][Math]::Ceiling($el.ActualHeight)
    if ($wd -le 0 -or $ht -le 0) { return }
    $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($wd, $ht, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($el)
    $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $fs = [System.IO.File]::Create($Path)
    try { $enc.Save($fs) } finally { $fs.Close() }
}

# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------
function Start-CSWGui {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(DontShow)][int]$AutoCloseSeconds = 0,
        [Parameter(DontShow)][string]$AutoRunAction,
        [Parameter(DontShow)][string]$ModulePath,
        [Parameter(DontShow)][string]$LogDumpPath,
        [Parameter(DontShow)][string]$ScreenshotPath,
        [Parameter(DontShow)][string]$StartModule,
        [Parameter(DontShow)][string]$SearchText,
        [Parameter(DontShow)][string]$WindowSize,
        [Parameter(DontShow)][switch]$HideLog
    )

    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'La interfaz gráfica requiere un hilo STA (ejecute PowerShell con -STA).'
    }
    if (-not (Get-Variable -Name CSW -Scope Global -ErrorAction SilentlyContinue)) { Initialize-CSWCore -RootPath $RootPath }
    if (-not $ModulePath) { $ModulePath = Join-Path $RootPath 'modules' }

    $script:CSWGui = @{
        Root             = $RootPath
        CorePath         = (Join-Path $RootPath 'core\CSW.Core.psm1')
        ModulePath       = $ModulePath
        C                = @{}
        B                = @{}
        Busy             = $false
        Ready            = $false
        Task             = $null
        SummaryPS        = $null
        SummaryHandle    = $null
        RunButtons       = (New-Object System.Collections.ArrayList)
        QuickTileButtons = (New-Object System.Collections.ArrayList)
        Cards            = (New-Object System.Collections.ArrayList)
        CardWidth        = 336
        Stopwatch        = (New-Object System.Diagnostics.Stopwatch)
        LogItems         = (New-Object 'System.Collections.ObjectModel.ObservableCollection[object]')
        LogVisible       = $true
        LogHeight        = 150
        LogUnread        = 0
        LogUnreadLevel   = ''
        ActionIndex      = @{}
        Modules          = @()
        CurrentModule    = $null
        AutoRunAction    = $AutoRunAction
        AutoClosing      = $false
        Runspace         = $null
        LastTimerError   = ''
        IconFont         = (New-Object System.Windows.Media.FontFamily('Segoe Fluent Icons, Segoe MDL2 Assets'))
    }
    $g = $script:CSWGui
    $g.B.Muted = ConvertTo-CSWGuiBrush '#64748B'
    $g.B.Ink = ConvertTo-CSWGuiBrush '#0F172A'
    $g.B.Accent = ConvertTo-CSWGuiBrush '#0B5CAD'

    # Instantánea de módulos/acciones (la GUI no vuelve a enumerar la lista compartida)
    $g.Modules = @(Get-CSWModule)
    foreach ($m in $g.Modules) { foreach ($a in @($m.Actions)) { if ($a) { $g.ActionIndex[[string]$a.FullId] = $a } } }

    # --- Ventana ---
    $g.Styles = [System.Windows.Markup.XamlReader]::Parse($script:CSWGuiStylesXaml)
    $xml = New-Object System.Xml.XmlDocument
    $xml.LoadXml($script:CSWGuiWindowXaml)
    # Los StaticResource de la ventana necesitan los estilos antes de cargar: se inyectan en Window.Resources
    $nsUri = 'http://schemas.microsoft.com/winfx/2006/xaml/presentation'
    $resNode = $xml.CreateElement('Window.Resources', $nsUri)
    $rdNode = $xml.CreateElement('ResourceDictionary', $nsUri)
    $mdNode = $xml.CreateElement('ResourceDictionary.MergedDictionaries', $nsUri)
    $stylesDoc = New-Object System.Xml.XmlDocument
    $stylesDoc.LoadXml($script:CSWGuiStylesXaml)
    [void]$mdNode.AppendChild($xml.ImportNode($stylesDoc.DocumentElement, $true))
    [void]$rdNode.AppendChild($mdNode)
    [void]$resNode.AppendChild($rdNode)
    [void]$xml.DocumentElement.PrependChild($resNode)
    $win = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xml))
    $g.Window = $win

    $names = 'VersionText', 'ComputerText', 'AdminBadge', 'AdminGlyph', 'AdminText', 'NavList', 'NavFooter1', 'NavFooter2',
    'DashView', 'DateText', 'KpiGrid', 'QuickSteps', 'QuickBtn', 'QuickTiles', 'RefreshBtn', 'SummaryLoading', 'SummaryGrid', 'TechBox', 'ClientBox', 'NotesBox',
    'ReportBtn', 'FolderBtn', 'ModuleTiles', 'ModuleView', 'ModGlyph', 'ModTitle', 'ModDesc', 'ModMeta', 'SearchBox', 'SearchHint', 'SearchClearBtn', 'ModCount',
    'CardsScroll', 'CardsPanel', 'NoResults', 'NoResultsText', 'NoResultsBtn', 'LogCount', 'AutoScrollChk', 'LogCopyBtn', 'LogClearBtn', 'LogHideBtn', 'LogList',
    'LogPanel', 'LogSplitter', 'LogRow', 'SplitRow', 'LogToggleBtn', 'LogToggleText', 'LogUnreadBadge', 'LogUnreadText',
    'StatusDot', 'StatusText', 'Progress', 'ElapsedText', 'CounterText', 'StopBtn'
    foreach ($n in $names) { $g.C[$n] = $win.FindName($n) }

    # --- Tamaño inicial: cabe en pantallas pequeñas (1366x768) ---
    try {
        $wa = [System.Windows.SystemParameters]::WorkArea
        if ($win.Width -gt $wa.Width * 0.96) { $win.Width = [Math]::Max($win.MinWidth, [Math]::Floor($wa.Width * 0.96)) }
        if ($win.Height -gt $wa.Height * 0.96) { $win.Height = [Math]::Max($win.MinHeight, [Math]::Floor($wa.Height * 0.96)) }
    }
    catch { }
    if ($WindowSize -match '^(\d+)x(\d+)$') {
        $win.MinWidth = 800; $win.MinHeight = 600
        $win.Width = [int]$Matches[1]; $win.Height = [int]$Matches[2]
    }
    try { $win.Icon = Get-CSWGuiLogoBitmap -Size 64 } catch { }

    # --- Barra superior ---
    $ver = [string]$global:CSW.Version
    if (-not $ver) { $ver = '1.0' }
    $g.C.VersionText.Text = "v$ver"
    $win.Title = "Cybersutro win v$ver - $env:COMPUTERNAME"
    $g.C.ComputerText.Text = $env:COMPUTERNAME
    $isAdmin = $false
    try { $isAdmin = [bool](Test-CSWAdmin) } catch { }
    $g.IsAdmin = $isAdmin
    if (-not $isAdmin) {
        $red = ConvertTo-CSWGuiBrush '#B91C1C'
        $g.C.AdminBadge.Background = ConvertTo-CSWGuiBrush '#FDECEC'
        $g.C.AdminBadge.BorderBrush = ConvertTo-CSWGuiBrush '#F3B4B4'
        $g.C.AdminGlyph.Foreground = $red; $g.C.AdminGlyph.Text = [string][char]0xE7BA
        $g.C.AdminText.Foreground = $red; $g.C.AdminText.Text = 'Sin privilegios'
        $g.C.AdminBadge.ToolTip = 'La herramienta no se ejecuta como administrador: muchas acciones fallarán.'
    }
    else { $g.C.AdminBadge.ToolTip = 'Ejecutándose como administrador: todas las acciones están disponibles.' }
    $g.C.NavFooter1.Text = ('Sesión iniciada a las {0}' -f ([datetime]$global:CSW.SessionStart).ToString('HH:mm', [System.Globalization.CultureInfo]::InvariantCulture))
    $g.C.NavFooter2.Text = [string]$global:CSW.DataPath
    $g.C.NavFooter2.ToolTip = [string]$global:CSW.LogFile

    # --- Navegación (agrupada) ---
    [void]$g.C.NavList.Items.Add((New-CSWGuiNavItem -Tag '__home' -Text 'Inicio' -Glyph (Get-CSWGuiGlyph 'home')))
    $lastGroup = ''
    foreach ($m in $g.Modules) {
        $grp = Get-CSWGuiNavGroup $m.Order
        if ($grp -ne $lastGroup) { [void]$g.C.NavList.Items.Add((New-CSWGuiNavHeader -Text $grp)); $lastGroup = $grp }
        $it = New-CSWGuiNavItem -Tag ([string]$m.Id) -Text ([string]$m.Name) -Glyph (Get-CSWGuiGlyph ("{0} {1}" -f $m.Icon, $m.Id)) -ToolTip ([string]$m.Description) -Count (@($m.Actions).Count)
        [void]$g.C.NavList.Items.Add($it)
    }
    $g.C.NavList.Add_SelectionChanged({
            param($s, $e)
            $it = $s.SelectedItem
            if (-not $it) { return }
            if ($it.Tag -eq '__home') { Show-CSWGuiDashboard } else { Show-CSWGuiModule -ModuleId ([string]$it.Tag) }
        })

    # --- Registro ---
    $g.C.LogList.ItemsSource = $g.LogItems
    $g.C.LogClearBtn.Add_Click({ param($s, $e) $script:CSWGui.LogItems.Clear(); Update-CSWGuiLogView })
    $g.C.LogCopyBtn.Add_Click({
            param($s, $e)
            $gg = $script:CSWGui
            $src = @($gg.C.LogList.SelectedItems)
            if ($src.Count -le 1) { $src = @($gg.LogItems) }
            $txt = ($src | ForEach-Object { $_.Text }) -join [Environment]::NewLine
            if ($txt) { try { [System.Windows.Clipboard]::SetText($txt) } catch { } }
            $gg.C.StatusText.Text = ('Copiadas {0} líneas del registro al portapapeles' -f $src.Count)
        })
    $g.C.LogHideBtn.Add_Click({ param($s, $e) Set-CSWGuiLogVisible -Visible $false })
    $g.C.LogToggleBtn.Add_Click({ param($s, $e) Set-CSWGuiLogVisible -Visible (-not $script:CSWGui.LogVisible) })
    $startLogVisible = $true
    try {
        if ($global:CSW.ContainsKey('GuiLogVisible')) { $startLogVisible = [bool]$global:CSW.GuiLogVisible }
        if ($global:CSW.ContainsKey('GuiLogHeight') -and [double]$global:CSW.GuiLogHeight -ge 90) { $g.LogHeight = [double]$global:CSW.GuiLogHeight }
    }
    catch { }
    if ($HideLog) { $startLogVisible = $false }
    Set-CSWGuiLogVisible -Visible $startLogVisible

    # --- Inicio ---
    Initialize-CSWGuiDashboard
    $g.C.QuickBtn.Add_Click({ param($s, $e) Invoke-CSWGuiQuickRepair })
    $g.C.RefreshBtn.Add_Click({ param($s, $e) Start-CSWGuiSummaryLoad })
    $g.C.ReportBtn.Add_Click({
            param($s, $e)
            if ($script:CSWGui.Busy -or -not $script:CSWGui.Ready) { return }
            [void](Start-CSWGuiTask -Kind 'Report' -Label 'Generando informe HTML' -Script $script:CSWGuiReportScript)
        })
    $g.C.FolderBtn.Add_Click({ param($s, $e) try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f (Get-CSWDataPath)) } catch { } })
    $g.C.DashView.Add_SizeChanged({ param($s, $e) Update-CSWGuiDashLayout })

    # --- Vista de módulo ---
    $g.C.SearchBox.Add_TextChanged({ param($s, $e) Update-CSWGuiFilter })
    $g.C.SearchClearBtn.Add_Click({ param($s, $e) $script:CSWGui.C.SearchBox.Text = ''; [void]$script:CSWGui.C.SearchBox.Focus() })
    $g.C.NoResultsBtn.Add_Click({ param($s, $e) $script:CSWGui.C.SearchBox.Text = ''; [void]$script:CSWGui.C.SearchBox.Focus() })
    $g.C.CardsScroll.Add_SizeChanged({ param($s, $e) Update-CSWGuiCardWidth })
    $g.C.CardsScroll.Add_ScrollChanged({ param($s, $e) if ($e.ViewportWidthChange -ne 0) { Update-CSWGuiCardWidth } })
    $g.C.StopBtn.Add_Click({ param($s, $e) Stop-CSWGuiTask })

    # --- Atajos ---
    $win.Add_PreviewKeyDown({
            param($s, $e)
            $gg = $script:CSWGui
            $ctrl = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)
            if ($e.Key -eq 'F' -and $ctrl) {
                if ($gg.C.ModuleView.Visibility -eq 'Visible') { [void]$gg.C.SearchBox.Focus(); $gg.C.SearchBox.SelectAll() }
                $e.Handled = $true
            }
            elseif ($e.Key -eq 'L' -and $ctrl) {
                Set-CSWGuiLogVisible -Visible (-not $gg.LogVisible)
                $e.Handled = $true
            }
            elseif ($e.Key -eq 'F5') {
                Select-CSWGuiNav -Tag '__home'
                Start-CSWGuiSummaryLoad
                $e.Handled = $true
            }
            elseif ($e.Key -eq 'Escape' -and $gg.C.SearchBox.IsKeyboardFocused) {
                $gg.C.SearchBox.Text = ''
            }
        })

    # --- Temporizador: log, fin de tareas, cronómetro ---
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({
            try {
                $gg = $script:CSWGui
                [void](Receive-CSWGuiLogQueue)
                if ($gg.Task -and $gg.Task.Handle.IsCompleted) { Complete-CSWGuiTask }
                if ($gg.SummaryPS -and $gg.SummaryHandle.IsCompleted) { Complete-CSWGuiSummaryLoad }
                if ($gg.Busy) {
                    $el = $gg.Stopwatch.Elapsed
                    $gg.C.ElapsedText.Text = ('{0:00}:{1:00}' -f [Math]::Floor($el.TotalMinutes), $el.Seconds)
                }
            }
            catch {
                # No se silencia: se muestra una vez cada error distinto (el temporizador corre cada 150 ms)
                try {
                    $m = [string]$_.Exception.Message
                    if ($script:CSWGui.LastTimerError -ne $m) {
                        $script:CSWGui.LastTimerError = $m
                        Add-CSWGuiLog -Message ("Error interno de la interfaz: {0}" -f $m) -Level Error
                        Update-CSWGuiLogView
                    }
                }
                catch { }
            }
        })
    $g.Timer = $timer

    # --- Cierre ---
    $win.Add_Closing({
            param($s, $e)
            $gg = $script:CSWGui
            if ($gg.AutoClosing) { return }
            if ($gg.Task) {
                $r = Show-CSWGuiMessage -Owner $s -Text ("Hay una acción en curso: {0}`n`nSi sale ahora se intentará detenerla; los procesos externos (sfc, dism...) podrían seguir ejecutándose.`n`n¿Desea salir de todos modos?" -f $gg.Task.Label) -Caption 'Salir de Cybersutro win' -Buttons 'YesNo' -Icon 'Warning' -Default 'No'
                if ($r -ne 'Yes') { $e.Cancel = $true; return }
            }
            $cnt = 0
            if ($global:CSW.History) { $cnt = $global:CSW.History.Count }
            if ($cnt -gt 0) {
                $r = Show-CSWGuiMessage -Owner $s -Text ("Se ejecutaron {0} acciones en esta sesión.`n`n¿Desea generar el informe HTML para el cliente antes de salir?" -f $cnt) -Caption 'Generar informe' -Buttons 'YesNoCancel' -Icon 'Question'
                if ($r -eq 'Cancel') { $e.Cancel = $true; return }
                if ($r -eq 'Yes') {
                    try { [void](Export-CSWReport -Open) }
                    catch { [void](Show-CSWGuiMessage -Owner $s -Text ("No se pudo generar el informe: {0}" -f $_.Exception.Message) -Caption 'Error' -Buttons 'OK' -Icon 'Error') }
                }
            }
        })
    $win.Add_Closed({
            $gg = $script:CSWGui
            try { $gg.Timer.Stop() } catch { }
            if ($gg.AutoCloseTimer) { try { $gg.AutoCloseTimer.Stop() } catch { } }
            $wasBusy = $false
            if ($gg.Task) {
                $wasBusy = $true
                try { [void]$gg.Task.PS.BeginStop($null, $null) } catch { }
            }
            if ($gg.SummaryPS) { try { [void]$gg.SummaryPS.BeginStop($null, $null) } catch { } }
            if ($gg.Runspace) {
                try { if ($wasBusy) { $gg.Runspace.CloseAsync() } else { $gg.Runspace.Close(); $gg.Runspace.Dispose() } } catch { }
            }
        })

    # --- Runspace de trabajo ---
    $global:CSW.GuiMode = $true
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
    $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('CSW', $global:CSW)
    $g.Runspace = $rs

    Add-CSWGuiLog -Message ('Cybersutro win v{0} - {1} módulos, {2} acciones. Log: {3}' -f $ver, $g.Modules.Count, $g.ActionIndex.Count, $global:CSW.LogFile) -Level Info
    if (-not $isAdmin) { Add-CSWGuiLog -Message 'Sin privilegios de administrador: muchas acciones fallarán.' -Level Warn }
    [void](Start-CSWGuiTask -Kind 'Init' -Label 'Iniciando motor de trabajo' -Script $script:CSWGuiInitScript -Arguments @{ State = $global:CSW; RootPath = $RootPath; ModulePath = $ModulePath })

    # --- Selección inicial ---
    if ($StartModule) { Select-CSWGuiNav -Tag $StartModule } else { Select-CSWGuiNav -Tag '__home' }
    if ($SearchText -and $g.CurrentModule) { $g.C.SearchBox.Text = $SearchText }
    Start-CSWGuiSummaryLoad
    Update-CSWGuiCounter
    Update-CSWGuiLogView

    # --- Autocierre (solo pruebas) ---
    if ($AutoCloseSeconds -gt 0) {
        $ac = New-Object System.Windows.Threading.DispatcherTimer
        $ac.Interval = [TimeSpan]::FromSeconds($AutoCloseSeconds)
        $g.AutoCloseShot = $ScreenshotPath
        $ac.Add_Tick({
                param($s, $e)
                $s.Stop()
                $gg = $script:CSWGui
                try { [void](Receive-CSWGuiLogQueue -Max 100000) } catch { }
                if ($gg.AutoCloseShot) { try { Save-CSWGuiScreenshot -Path $gg.AutoCloseShot } catch { Add-CSWGuiLog -Message ("Captura fallida: {0}" -f $_.Exception.Message) -Level Error } }
                $gg.AutoClosing = $true
                $gg.Window.Close()
            })
        $g.AutoCloseTimer = $ac
        $ac.Start()
    }

    $timer.Start()
    try {
        [void]$win.ShowDialog()
    }
    finally {
        try { [void](Receive-CSWGuiLogQueue -Max 100000) } catch { }
        if ($LogDumpPath) {
            try { (@($g.LogItems) | ForEach-Object { '[{0}] {1}' -f $_.Level, $_.Text }) | Set-Content -LiteralPath $LogDumpPath -Encoding UTF8 } catch { }
        }
        $global:CSW.GuiMode = $false
    }
}
